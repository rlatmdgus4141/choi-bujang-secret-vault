import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { isIP } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { decide } from './decide.mjs';
import { decide as vaultDecide } from '../../src/decider.mjs';

const DEFAULT_RULE_PATH = new URL('../runtime/known-cve-deny-rules.json', import.meta.url);
const DEFAULT_LOG_PATH = new URL('../alerts.log', import.meta.url);
const SOURCE = 'xdr.known-cve';
const TTL_MS = 15 * 60 * 1000;
const MAX_ALERT_AGE_MS = 5 * 60 * 1000;
const locks = new Map();

function canonicalIp(value) {
  if (typeof value !== 'string' || !isIP(value)) return null;
  return isIP(value) === 6 ? new URL(`http://[${value}]/`).hostname.slice(1, -1) : value;
}

function ruleId(ip) {
  return `${SOURCE}.${createHash('sha256').update(ip).digest('hex').slice(0, 24)}`;
}

function validRule(rule) {
  return rule && rule.source === SOURCE && rule.action === 'deny'
    && canonicalIp(rule.sourceIp) === rule.sourceIp && rule.id === ruleId(rule.sourceIp)
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
  const key = String(path);
  const previous = locks.get(key) ?? Promise.resolve();
  const pending = previous.catch(() => {}).then(task);
  locks.set(key, pending);
  return pending.finally(() => { if (locks.get(key) === pending) locks.delete(key); });
}

async function writeRules(path, rules) {
  const target = path instanceof URL ? new URL(path) : path;
  const directory = target instanceof URL ? new URL('./', target) : dirname(target);
  await mkdir(directory, { recursive: true });
  const temporary = target instanceof URL ? new URL(`${target.href}.${randomUUID()}.tmp`) : `${target}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules }, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, target);
}

// Only a trusted Wazuh/fixture caller invokes this module. No public ingestion route is added.
// Recompute the decision instead of trusting a caller's claimed confidence or action.
export async function respond(alert, { rulePath = DEFAULT_RULE_PATH, logPath = DEFAULT_LOG_PATH, now = Date.now() } = {}) {
  if (!Number.isFinite(now)) throw new TypeError('invalid_response_time');
  const decision = decide(alert);
  const alertId = typeof alert?.id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}$/u.test(alert.id) ? alert.id : null;
  const ip = canonicalIp(alert?.data?.srcip);
  const occurredAt = typeof alert?.timestamp === 'string' ? Date.parse(alert.timestamp) : NaN;
  const fresh = Number.isFinite(occurredAt) && now >= occurredAt && now - occurredAt <= MAX_ALERT_AGE_MS;
  return serial(rulePath, async () => {
    const current = await readRules(rulePath);
    const active = current.filter(rule => Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now);
    let addedRule = null;
    if (decision.action === 'block' && decision.confidence >= 0.85 && alertId && ip && fresh) {
      const id = ruleId(ip);
      const existing = active.find(rule => rule.id === id);
      // Duplicate delivery must not renew an IP ban or append duplicate evidence.
      if (!existing?.evidenceAlertIds.includes(alertId)) {
        addedRule = {
          id, source: SOURCE, action: 'deny', sourceIp: ip,
          createdAt: new Date(now).toISOString(), expiresAt: new Date(now + TTL_MS).toISOString(),
          evidenceAlertIds: [...new Set([...(existing?.evidenceAlertIds ?? []), alertId])].slice(-100),
        };
        const previousIndex = active.findIndex(rule => rule.id === id);
        if (previousIndex < 0) active.push(addedRule); else active[previousIndex] = addedRule;
      }
    }
    if (addedRule || active.length !== current.length) await writeRules(rulePath, active);
    const directory = logPath instanceof URL ? new URL('./', logPath) : dirname(logPath);
    await mkdir(directory, { recursive: true });
    // Whitelisted audit fields only: no raw alert, account, password, JWT, or message interpolation.
    await appendFile(logPath, `${JSON.stringify({
      at: new Date(now).toISOString(), alertId, action: decision.action, confidence: decision.confidence,
      reason: decision.reason, ruleId: addedRule?.id ?? null, expiresAt: addedRule?.expiresAt ?? null,
      response: addedRule ? 'deny_rule_added' : decision.action === 'block' && !fresh ? 'stale_alert_no_block' : 'logged_only',
    })}\n`, { mode: 0o600 });
    return { decision, addedRule };
  });
}

export async function findDenyRule(sourceIp, { rulePath = DEFAULT_RULE_PATH, now = Date.now() } = {}) {
  const ip = canonicalIp(sourceIp);
  if (!ip || !Number.isFinite(now)) return null;
  const rules = await readRules(rulePath);
  return rules.find(rule => rule.sourceIp === ip && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now) ?? null;
}

// Additional gate only. The verified 18-field request is passed unchanged to the existing decider.
// The current engine contract has no source IP: obtain it via a trusted server-side resolver, never request/body/header fields.
// The caller supplies its registered deny response; do not invent an operational reasonCode here.
export function createXdrGate(baseDecide, { trustedSourceIpForRequest, denyResponse, rulePath = DEFAULT_RULE_PATH, clock = Date.now } = {}) {
  if (typeof baseDecide !== 'function' || typeof trustedSourceIpForRequest !== 'function' || typeof denyResponse !== 'function') {
    throw new TypeError('trusted_xdr_gate_callbacks_required');
  }
  return async request => {
    const ip = await trustedSourceIpForRequest(request);
    const rule = await findDenyRule(ip, { rulePath, now: clock() });
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

// The concrete connection to this repository's unchanged ZTNA policy.
export function createVaultXdrGate(options) {
  return createXdrGate(vaultDecide, options);
}
