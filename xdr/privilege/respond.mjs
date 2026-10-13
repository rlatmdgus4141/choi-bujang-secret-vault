import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { decide } from './decide.mjs';
import { decide as vaultDecide } from '../../src/decider.mjs';

const DEFAULT_RULE_PATH = new URL('../runtime/privilege-deny-rules.json', import.meta.url);
const DEFAULT_LOG_PATH = new URL('../alerts.log', import.meta.url);
const SOURCE = 'xdr.privilege';
const TTL_MS = 15 * 60 * 1000;
const MAX_ALERT_AGE_MS = 5 * 60 * 1000;
const locks = new Map();

function canonicalIp(value) {
  if (typeof value !== 'string' || !isIP(value)) return null;
  return isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
}
function identifier(value) {
  return typeof value === 'string' && value === value.trim() && value.length > 0 && value.length <= 160
    && !/[\u0000-\u001f\u007f]/u.test(value) && !/^(?:sb_secret_|sb_publishable_|eyJ|Bearer\s)/u.test(value);
}
function targetFingerprint(target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) return null;
  let parts;
  if (target.scope === 'account_source') {
    if (Object.keys(target).sort().join(',') !== 'account,agent,scope,sourceIp'
        || !identifier(target.agent) || !identifier(target.account)) return null;
    const ip = canonicalIp(target.sourceIp);
    if (!ip) return null;
    parts = [target.scope, target.agent, target.account, ip];
  } else if (target.scope === 'session') {
    if (Object.keys(target).sort().join(',') !== 'namespace,scope,sessionId'
        || !identifier(target.namespace) || !identifier(target.sessionId)) return null;
    parts = [target.scope, target.namespace, target.sessionId];
  } else return null;
  return { scope: target.scope, targetHash: createHash('sha256').update(JSON.stringify(parts)).digest('hex') };
}
function ruleId(hash) { return `${SOURCE}.${hash.slice(0, 24)}`; }
function validRule(rule) {
  return rule && rule.source === SOURCE && rule.action === 'deny'
    && ['account_source', 'session'].includes(rule.scope) && /^[a-f0-9]{64}$/u.test(rule.targetHash ?? '')
    && rule.id === ruleId(rule.targetHash)
    && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt))
    && Date.parse(rule.expiresAt) > Date.parse(rule.createdAt)
    && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= TTL_MS
    && Array.isArray(rule.evidenceAlertIds) && rule.evidenceAlertIds.length > 0
    && rule.evidenceAlertIds.every(id => typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/u.test(id));
}
async function readRules(path) {
  let raw;
  try { raw = await readFile(path, 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw new Error('xdr_rule_store_unavailable'); }
  let store;
  try { store = JSON.parse(raw); } catch { throw new Error('invalid_xdr_rule_store'); }
  if (store?.schema !== 'aleph.xdr.deny-rules.v1' || !Array.isArray(store.rules) || !store.rules.every(validRule)) {
    throw new Error('invalid_xdr_rule_store');
  }
  return store.rules;
}
function serial(path, task) {
  const key = String(path), previous = locks.get(key) ?? Promise.resolve();
  const pending = previous.catch(() => {}).then(task); locks.set(key, pending);
  return pending.finally(() => { if (locks.get(key) === pending) locks.delete(key); });
}
async function writeRules(path, rules) {
  const target = path instanceof URL ? new URL(path) : path;
  await mkdir(target instanceof URL ? new URL('./', target) : dirname(target), { recursive: true });
  const temporary = target instanceof URL ? new URL(`${target.href}.${randomUUID()}.tmp`) : `${target}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, target);
}

// Training feed mapping only. A production server must resolve its registered identity/session.
export function fixtureTargetForAlert(alert) {
  return { scope: 'account_source', agent: alert?.agent?.id || alert?.agent?.name,
    account: alert?.data?.srcuser, sourceIp: alert?.data?.srcip };
}

// No public ingestion endpoint. Recompute the decision; never accept a claimed block result.
export async function respond(alert, { rulePath = DEFAULT_RULE_PATH, logPath = DEFAULT_LOG_PATH,
  now = Date.now(), trustedTargetForAlert = fixtureTargetForAlert } = {}) {
  if (!Number.isFinite(now) || typeof trustedTargetForAlert !== 'function') throw new TypeError('invalid_response_configuration');
  const decision = decide(alert);
  const alertId = typeof alert?.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/u.test(alert.id) ? alert.id : null;
  const target = targetFingerprint(await trustedTargetForAlert(alert));
  const occurredAt = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
  const fresh = Number.isFinite(occurredAt) && now >= occurredAt && now - occurredAt <= MAX_ALERT_AGE_MS;
  return serial(rulePath, async () => {
    const current = await readRules(rulePath);
    const active = current.filter(rule => Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now);
    let addedRule = null;
    if (decision.action === 'block' && decision.confidence >= 0.85 && alertId && target && fresh) {
      const id = ruleId(target.targetHash), existing = active.find(rule => rule.id === id);
      if (!existing?.evidenceAlertIds.includes(alertId)) {
        addedRule = { id, source: SOURCE, action: 'deny', ...target,
          createdAt: new Date(now).toISOString(), expiresAt: new Date(now + TTL_MS).toISOString(),
          evidenceAlertIds: [...new Set([...(existing?.evidenceAlertIds ?? []), alertId])].slice(-100) };
        const index = active.findIndex(rule => rule.id === id);
        if (index < 0) active.push(addedRule); else active[index] = addedRule;
      }
    }
    if (addedRule || active.length !== current.length) await writeRules(rulePath, active);
    await mkdir(logPath instanceof URL ? new URL('./', logPath) : dirname(logPath), { recursive: true });
    await appendFile(logPath, `${JSON.stringify({ at: new Date(now).toISOString(), alertId,
      action: decision.action, confidence: decision.confidence, reason: decision.reason,
      scope: target?.scope ?? null, ruleId: addedRule?.id ?? null, expiresAt: addedRule?.expiresAt ?? null,
      response: addedRule ? 'access_revocation_added' : decision.action === 'block' && !fresh ? 'stale_alert_no_block' : 'logged_only',
    })}\n`, { mode: 0o600 });
    return { decision, addedRule };
  });
}
export async function findDenyRule(target, { rulePath = DEFAULT_RULE_PATH, now = Date.now() } = {}) {
  const fingerprint = targetFingerprint(target);
  if (!fingerprint || !Number.isFinite(now)) return null;
  const rules = await readRules(rulePath);
  return rules.find(rule => rule.scope === fingerprint.scope && rule.targetHash === fingerprint.targetHash
    && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now) ?? null;
}

// Resolve a verified target outside the request. No browser account, source IP or session claim is read.
export function createXdrGate(baseDecide, { trustedTargetForRequest, denyResponse,
  rulePath = DEFAULT_RULE_PATH, clock = Date.now } = {}) {
  if (typeof baseDecide !== 'function' || typeof trustedTargetForRequest !== 'function' || typeof denyResponse !== 'function') {
    throw new TypeError('trusted_xdr_gate_callbacks_required');
  }
  return async request => {
    const target = await trustedTargetForRequest(request);
    const rule = await findDenyRule(target, { rulePath, now: clock() });
    if (rule) {
      const response = await denyResponse(request, rule);
      if (response?.schema !== 'aleph.decision.v1' || response.requestId !== request.requestId
          || response.decision !== 'deny' || !Array.isArray(response.ruleIds) || !response.ruleIds.includes(rule.id)
          || typeof response.reasonCode !== 'string' || !response.reasonCode
          || Object.keys(response).sort().join(',') !== 'decision,reasonCode,requestId,ruleIds,schema') {
        throw new Error('invalid_registered_xdr_deny_response');
      }
      return response;
    }
    return baseDecide(request);
  };
}
export function createVaultXdrGate(options) { return createXdrGate(vaultDecide, options); }
