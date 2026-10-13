import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/privilege/decide.mjs';
import { projectAlerts, readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { respond, findDenyRule, fixtureTargetForAlert, createXdrGate, createVaultXdrGate } from '../xdr/privilege/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayPrivilege } from '../scripts/xdr-privilege-replay.mjs';

const root = new URL('../', import.meta.url);
const bytes = await readFile(new URL('xdr/fixtures/privilege.json', root));
const fixture = JSON.parse(bytes);
const clear = fixture.alerts[0], ambiguous = fixture.alerts[9], normal = fixture.alerts[17];
const at = Date.parse(clear.timestamp);
async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-privilege-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('privilege projection preserves the official fixture and yields 26 rows with five sanitized fields', async () => {
  assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),
    '442fc3297bcc73969fa61b1368d08e0038b9c135');
  const rows = await readAlerts();
  assert.equal(rows.length, 26);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'account,description,level,sourceIp,timestamp'));
  const secret = ['sb', 'secret', 'x'.repeat(1200)].join('_');
  const jwt = ['eyJ' + 'a'.repeat(1000), 'eyJ' + 'b'.repeat(1000), 'c'.repeat(1000)].join('.');
  const out = JSON.stringify(projectAlerts([{ ...clear, data: { ...clear.data, srcuser: 'private' + '@example.invalid' },
    rule: { level: 12, description: `password="${secret}" Bearer ${jwt}\nextra` } }]));
  for (const value of [secret.slice(0, 100), jwt.slice(0, 100), 'private' + '@example.invalid']) assert.equal(out.includes(value), false);
});

test('privilege patterns are grounded constants and classification is stateless with 9/8/9 decisions', async () => {
  const source = await readFile(new URL('xdr/privilege/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/privilege/patterns.json', root), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns);
  assert.ok(patterns.every(p => p.evidence && p.source.startsWith('https://attack.mitre.org/')));
  assert.doesNotMatch(source, /\bimport\s*(?:\(|[{'"*])/u);
  assert.doesNotMatch(source, /\b(?:fetch|eval|Function|readFile|writeFile)\s*\(/u);
  const before = JSON.stringify(fixture), answers = fixture.alerts.map(decide);
  assert.deepEqual([...fixture.alerts].reverse().map(decide).reverse(), answers);
  assert.equal(JSON.stringify(fixture), before);
  const counts = { block: 0, alert: 0, record: 0 };
  for (const out of answers) {
    counts[out.action]++;
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    assert.equal(out.action, out.confidence >= 0.85 ? 'block' : out.confidence >= 0.5 ? 'alert' : 'record');
    assert.doesNotMatch(out.reason, /[\r\n]/u);
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
  assert.ok(answers.slice(9, 17).every(out => out.action === 'alert'));
  assert.ok(answers.slice(17).every(out => out.action === 'record'));
});

test('new accounts, addresses and equivalent privilege changes are detected without username exceptions', () => {
  const event = (description, group, tags = ['T1078']) => ({ id: 'unseen-event',
    rule: { level: 12, description, mitre: { id: tags } },
    data: { srcip: '2001:db8::25', srcuser: 'unseen-account', ...(group ? { group } : {}) } });
  for (const item of [
    event('Account added to administrator group from remote source.', 'administrators'),
    event('An unapproved promotion added the account to admin group from unfamiliar network.', 'domain admins', ['T1098.007']),
    event('Newly elevated session executed an administrator command.', null, ['T1068']),
    event('Session elevated to administrator from an unseen address.', null, ['T1068']),
    event('Privileged command execution outside normal hours from unfamiliar network.', null, ['T1068']),
    event('Account used another account credentials for administrator command.', null, ['T1068']),
    { ...event('Account removed from admin group and re-added in 60 seconds.', 'administrators'),
      data: { ...event('').data, group: 'administrators', count: 2 } },
  ]) assert.equal(decide(item).action, 'block');
  const changed = { ...clear, id: 'different-id', timestamp: '2026-10-01T00:00:00Z',
    data: { srcip: '198.51.100.99', srcuser: 'different-account', group: 'administrators' } };
  assert.deepEqual(decide(changed), decide(clear));
});

test('normal groups, cancelled/failed promotion, single time signals and conflicting summaries never auto-block', () => {
  const patch = (description, data = {}, rule = {}) => ({ ...clear, rule: { ...clear.rule, description, ...rule }, data: { ...clear.data, ...data } });
  for (const item of [
    patch('관리자 그룹은 아닙니다. 과제 그룹에 추가됐습니다.', { group: 'course-team' }),
    patch('관리자 그룹 추가와 관리자 명령이 실패했습니다.'),
    patch('권한 상승 창을 취소했습니다.'),
    patch('새 관리자가 되었으나 명령은 없습니다.'),
    patch('평소 주소에서 관리자 명령이 실행됐습니다.'),
    patch('Administrator command executed outside business hours.'),
    patch('Group membership read-only; no privilege change.'),
    patch('Approved change added the user to admin group from remote address.'),
    patch('Admin session privileges removed from an unseen source.', {}, { mitre: ['T1068'] }),
    patch('같은 주소에서 계정 4개가 관리자 그룹에 추가됐습니다.', { count: 3 }),
    patch('관리자 그룹에서 제거되고 1일 뒤 다시 관리자 그룹에 들어왔습니다.', { count: 2 }),
    patch(clear.rule.description, { srcuser: undefined }), patch(clear.rule.description, { srcip: 'invalid' }),
    patch(clear.rule.description, { group: {} }), patch(clear.rule.description, {}, { level: 7 }),
  ]) assert.notEqual(decide(item).action, 'block');
  for (const item of [null, [], '', {}, { rule: { level: 16, mitre: ['T1078'] } }]) assert.notEqual(decide(item).action, 'block');
  for (const srcuser of ['admin-new', 'service-account', 'ordinary-new']) {
    assert.equal(decide({ ...normal, id: 'normal-new', data: { srcip: '198.51.100.88', srcuser } }).action, 'record');
  }
});

test('privilege decide runs as one module in an empty VM without imports, Node globals or network', () => {
  const script = `
    const fs = require('node:fs'); const vm = require('node:vm');
    (async () => {
      const context = vm.createContext({});
      const mod = new vm.SourceTextModule(fs.readFileSync(process.argv[1], 'utf8'), { context });
      await mod.link(() => { throw new Error('imports_forbidden'); });
      await mod.evaluate({ timeout: 1000 }); context.call = mod.namespace.decide;
      const counts = { block: 0, alert: 0, record: 0 };
      for (const alert of JSON.parse(fs.readFileSync(process.argv[2], 'utf8')).alerts) {
        context.input = alert; counts[vm.runInContext('call(input)', context, { timeout: 1000 }).action]++;
      }
      process.stdout.write(JSON.stringify(counts));
    })().catch(() => { process.exitCode = 1; });`;
  const out = execFileSync(process.execPath, ['--experimental-vm-modules', '-e', script,
    new URL('xdr/privilege/decide.mjs', root).pathname, new URL('xdr/fixtures/privilege.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 9, alert: 8, record: 9 });
});

test('fresh candidates create expiring hashed access rules and duplicate delivery never extends them', async t => {
  const paths = await temporary(t);
  for (const alert of [ambiguous, normal]) assert.equal((await respond(alert, { ...paths, now: Date.parse(alert.timestamp) })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at - 1 })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at + 6 * 60 * 1000 })).addedRule, null);
  const secret = ['sb', 'secret', 'x'.repeat(24)].join('_');
  const out = await respond({ ...clear, full_log: secret, data: { ...clear.data, password: secret } }, { ...paths, now: at });
  assert.equal(out.addedRule.scope, 'account_source');
  assert.equal(Date.parse(out.addedRule.expiresAt), at + 15 * 60 * 1000);
  assert.deepEqual(out.addedRule.evidenceAlertIds, [clear.id]);
  await respond(clear, { ...paths, now: at + 1000 });
  const target = fixtureTargetForAlert(clear);
  assert.equal(Date.parse((await findDenyRule(target, { ...paths, now: at + 1000 })).expiresAt), at + 15 * 60 * 1000);
  const other = { ...clear, id: 'other-evidence', timestamp: new Date(at + 2000).toISOString() };
  await Promise.all([respond(clear, { ...paths, now: at + 2000 }), respond(other, { ...paths, now: at + 2000 })]);
  const rule = await findDenyRule(target, { ...paths, now: at + 3000 });
  assert.deepEqual(new Set(rule.evidenceAlertIds), new Set([clear.id, other.id]));
  assert.equal(await findDenyRule(target, { ...paths, now: Date.parse(rule.expiresAt) }), null);
  const stored = (await readFile(paths.rulePath, 'utf8')) + (await readFile(paths.logPath, 'utf8'));
  for (const value of [secret, clear.data.srcuser, clear.data.srcip, clear.rule.description]) assert.equal(stored.includes(value), false);
});

test('account/source mapping does not block other accounts sharing an IP or the normal account context', async t => {
  const paths = await temporary(t); await respond(clear, { ...paths, now: at });
  const target = fixtureTargetForAlert(clear);
  assert.ok(await findDenyRule(target, { ...paths, now: at }));
  assert.equal(await findDenyRule({ ...target, account: 'another-account' }, { ...paths, now: at }), null);
  assert.equal(await findDenyRule({ ...target, sourceIp: '198.51.100.99' }, { ...paths, now: at }), null);
  assert.equal(await findDenyRule({ ...target, agent: 'another-managed-host' }, { ...paths, now: at }), null);
  const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'fixture-request', account: clear.data.srcuser, sourceIp: clear.data.srcip });
  const verdict = Object.freeze({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'step_up', reasonCode: 'fixture_step_up', ruleIds: ['fixture.base'] });
  const base = seen => { assert.equal(seen, request); return verdict; };
  const options = { rulePath: paths.rulePath, clock: () => at,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }) };
  for (const trusted of [null, { ...target, account: 'another-account' }]) {
    assert.equal(await createXdrGate(base, { ...options, trustedTargetForRequest: () => trusted })(request), verdict);
  }
  assert.equal((await createXdrGate(base, { ...options, trustedTargetForRequest: () => target })(request)).decision, 'deny');
  assert.deepEqual(await createVaultXdrGate({ ...options, trustedTargetForRequest: () => null })(request), await originalDecide(request));
  assert.throws(() => createXdrGate(base), /trusted_xdr_gate_callbacks_required/u);
});

test('a server-confirmed session can be revoked across network changes without targeting other sessions', async t => {
  const paths = await temporary(t);
  const target = { scope: 'session', namespace: 'class.project.auth', sessionId: 'opaque-session-one' };
  const out = await respond(clear, { ...paths, now: at, trustedTargetForAlert: () => target });
  assert.equal(out.addedRule.scope, 'session');
  assert.ok(await findDenyRule(target, { ...paths, now: at }));
  assert.equal(await findDenyRule({ ...target, sessionId: 'opaque-session-two' }, { ...paths, now: at }), null);
  assert.equal(await findDenyRule({ ...target, namespace: 'another.project' }, { ...paths, now: at }), null);
  const request = { schema: 'aleph.decision.v1', requestId: 'changed-network-request', sourceIp: '198.51.100.88' };
  const gate = createXdrGate(() => { throw new Error('revoked session reached base policy'); }, {
    rulePath: paths.rulePath, clock: () => at, trustedTargetForRequest: () => target,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }),
  });
  assert.equal((await gate(request)).decision, 'deny');
  const store = await readFile(paths.rulePath, 'utf8');
  assert.equal(store.includes(target.sessionId), false);
});

test('privilege fixture replay revokes 9 candidates and passes all 9 normal requests', async t => {
  const report = await replayPrivilege({ root, ...await temporary(t) });
  assert.deepEqual(report.counts, { block: 9, alert: 8, record: 9 });
  assert.equal(report.rulesAdded, 9);
  assert.equal(report.blockedCandidatesDenied, 9);
  assert.equal(report.normalEvents, 9);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});
