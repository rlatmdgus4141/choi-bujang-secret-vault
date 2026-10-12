import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { decide } from '../xdr/brute-force/decide.mjs';
import { readAlerts, projectAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { respond, findDenyRule, createXdrGate, createVaultXdrGate } from '../xdr/brute-force/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayBruteForce } from '../scripts/xdr-replay.mjs';

const root = new URL('../', import.meta.url);
const rawFixture = await readFile(new URL('xdr/fixtures/brute-force.json', root));
const fixture = JSON.parse(rawFixture);
const clear = fixture.alerts[0];
const ambiguous = fixture.alerts[10];
const normal = fixture.alerts[19];
const at = Date.parse(clear.timestamp);

async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-xdr-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('official fixture stays unchanged; projection has exactly five sanitized fields for all alerts', async () => {
  const header = Buffer.from(`blob ${rawFixture.length}\0`);
  const blob = createHash('sha1').update(header).update(rawFixture).digest('hex');
  assert.equal(blob, '5180c420756dd6e8d8b73ca8ccffe11926e4f754');
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'account,description,level,sourceIp,timestamp'));
  const secret = 'sb_' + 'secret_' + 'x'.repeat(24);
  const token = ['eyJ' + 'a'.repeat(20), 'eyJ' + 'b'.repeat(20), 'c'.repeat(20)].join('.');
  const email = 'private' + '@' + 'example.invalid';
  const projected = JSON.stringify(projectAlerts([{ timestamp: clear.timestamp,
    data: { srcip: clear.data.srcip, srcuser: email, password: secret, token },
    rule: { level: 12, description: `password="${secret}" Bearer ${token}\n${email}` } }]));
  for (const value of [secret, token, email]) assert.ok(!projected.includes(value));
});

test('constant patterns match the grounded catalog; decisions are stateless and preserve input', async () => {
  const source = await readFile(new URL('xdr/brute-force/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/brute-force/patterns.json', root), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns);
  assert.ok(patterns.every(p => p.evidence && p.source.startsWith('https://attack.mitre.org/')));
  assert.doesNotMatch(source, /\bimport\s*(?:\(|[{'"*])/u);
  const before = JSON.stringify(fixture);
  const answers = fixture.alerts.map(decide);
  assert.deepEqual([...fixture.alerts].reverse().map(decide).reverse(), answers);
  assert.equal(JSON.stringify(fixture), before);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const answer of answers) {
    counts[answer.action]++;
    assert.deepEqual(Object.keys(answer).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(answer.confidence) && answer.confidence >= 0 && answer.confidence <= 1);
    assert.equal(answer.action, answer.confidence >= 0.85 ? 'block' : answer.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(answer.reason, /[\r\n]/u);
  }
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
});

test('singleton failures, missing correlation, conflicting counts, slow windows and normal success never auto-block', () => {
  const changed = (rule, data) => ({ ...clear, rule: { ...clear.rule, ...rule }, data: { ...clear.data, ...data } });
  assert.equal(decide(changed({ description: '로그인 실패 1건입니다.' }, { count: '1' })).action, 'alert');
  assert.equal(decide(changed({ mitre: [] }, {})).action, 'alert');
  assert.equal(decide(changed({}, { srcip: '999.1.1.1' })).action, 'alert');
  assert.equal(decide(changed({}, { srcuser: '' })).action, 'alert');
  assert.equal(decide(changed({}, { count: '999' })).action, 'alert');
  assert.equal(decide(changed({ description: '한 계정에서 24시간 동안 로그인 실패 48건입니다.' }, {})).action, 'alert');
  assert.equal(decide(changed({ description: '로그인이 성공했습니다.' }, { count: '999' })).action, 'record');
  for (const value of [null, [], '', {}, { rule: { level: 16, mitre: ['T1110'] } }]) {
    assert.equal(decide(value).action, 'record');
  }
  assert.equal(decide(changed({}, { srcip: ':1:2:3:4:5:6:7:8' })).action, 'alert');
});

test('decide.mjs runs alone inside a VM without imports, Node globals, network or file access', () => {
  const script = `
    const fs = require('node:fs'); const vm = require('node:vm');
    (async () => {
      const context = vm.createContext({});
      const source = fs.readFileSync(process.argv[1], 'utf8');
      const mod = new vm.SourceTextModule(source, { context });
      await mod.link(() => { throw new Error('imports_forbidden'); });
      await mod.evaluate({ timeout: 1000 });
      context.call = mod.namespace.decide;
      const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
      const counts = { block: 0, alert: 0, record: 0 };
      for (const alert of fixture.alerts) {
        context.input = alert;
        const answer = vm.runInContext('call(input)', context, { timeout: 1000 });
        counts[answer.action]++;
      }
      process.stdout.write(JSON.stringify(counts));
    })().catch(() => { process.exitCode = 1; });
  `;
  const out = execFileSync(process.execPath, ['--experimental-vm-modules', '-e', script,
    new URL('xdr/brute-force/decide.mjs', root).pathname, new URL('xdr/fixtures/brute-force.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 10, alert: 9, record: 9 });
});

test('only fresh clear attacks create deny rules; logs exclude raw credentials and input descriptions', async t => {
  const paths = await temporary(t);
  assert.equal((await respond(ambiguous, { ...paths, now: Date.parse(ambiguous.timestamp) })).addedRule, null);
  assert.equal((await respond(normal, { ...paths, now: Date.parse(normal.timestamp) })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at + 6 * 60 * 1000 })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at - 1 })).addedRule, null);
  const secret = 'sb_' + 'secret_' + 'x'.repeat(24);
  const enriched = { ...clear, data: { ...clear.data, password: secret, token: secret }, full_log: secret };
  const out = await respond(enriched, { ...paths, now: at });
  assert.ok(out.addedRule);
  assert.equal(Date.parse(out.addedRule.expiresAt), at + 15 * 60 * 1000);
  assert.deepEqual(out.addedRule.evidenceAlertIds, [clear.id]);
  const log = await readFile(paths.logPath, 'utf8');
  assert.ok(!log.includes(secret));
  assert.ok(!log.includes(clear.rule.description));
  assert.equal(log.trim().split('\n').length, 5);
});

test('duplicate evidence does not renew the ban; concurrent clear alerts merge evidence; expired bans stop matching', async t => {
  const paths = await temporary(t);
  await respond(clear, { ...paths, now: at });
  await respond(clear, { ...paths, now: at + 1000 });
  const first = await findDenyRule(clear.data.srcip, { ...paths, now: at + 1000 });
  assert.equal(Date.parse(first.expiresAt), at + 15 * 60 * 1000);
  const other = { ...clear, id: 'parallel-evidence', timestamp: new Date(at + 2000).toISOString() };
  await Promise.all([respond(other, { ...paths, now: at + 2000 }), respond(clear, { ...paths, now: at + 2000 })]);
  const merged = await findDenyRule(clear.data.srcip, { ...paths, now: at + 3000 });
  assert.deepEqual(new Set(merged.evidenceAlertIds), new Set([clear.id, other.id]));
  assert.equal(await findDenyRule(clear.data.srcip, { ...paths, now: Date.parse(merged.expiresAt) }), null);
});

test('the extra gate preserves the base verdict and request; browser-claimed source fields cannot select a ban', async t => {
  const paths = await temporary(t);
  await respond(clear, { ...paths, now: at });
  const verdict = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'fixture-request',
    decision: 'step_up', reasonCode: 'fixture_step_up', ruleIds: ['fixture.existing'] });
  let calls = 0;
  const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'fixture-request', sourceIp: clear.data.srcip });
  const base = seen => { calls++; assert.equal(seen, request); return verdict; };
  const denial = (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
    decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] });
  const safe = createXdrGate(base, { rulePath: paths.rulePath, clock: () => at,
    trustedSourceIpForRequest: () => normal.data.srcip, denyResponse: denial });
  assert.equal(await safe(request), verdict);
  const absent = createXdrGate(base, { rulePath: paths.rulePath, clock: () => at,
    trustedSourceIpForRequest: () => null, denyResponse: denial });
  assert.equal(await absent(request), verdict);
  const blocked = createXdrGate(base, { rulePath: paths.rulePath, clock: () => at,
    trustedSourceIpForRequest: () => clear.data.srcip, denyResponse: denial });
  assert.equal((await blocked(request)).decision, 'deny');
  assert.equal(calls, 2);
  assert.throws(() => createXdrGate(base), /trusted_xdr_gate_callbacks_required/u);
  const actual = createVaultXdrGate({ rulePath: paths.rulePath, clock: () => at,
    trustedSourceIpForRequest: () => normal.data.srcip, denyResponse: denial });
  assert.deepEqual(await actual(request), await originalDecide(request));
});

test('chronological training replay blocks candidates and permits all nine normal fixture requests through the fixture base policy', async t => {
  const paths = await temporary(t);
  const report = await replayBruteForce({ root, ...paths });
  assert.deepEqual(report.counts, { block: 10, alert: 9, record: 9 });
  assert.equal(report.rulesAdded, 10);
  assert.equal(report.blockedCandidatesDenied, 10);
  assert.equal(report.normalEvents, 9);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});
