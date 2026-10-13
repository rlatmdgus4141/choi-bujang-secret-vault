import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/persistence/decide.mjs';
import { projectAlerts, readAlerts } from '../xdr/persistence/read-alerts.mjs';
import { respond, findDenyRule, createXdrGate, createVaultXdrGate } from '../xdr/persistence/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayPersistence } from '../scripts/xdr-persistence-replay.mjs';

const root = new URL('../', import.meta.url);
const bytes = await readFile(new URL('xdr/fixtures/persistence.json', root));
const fixture = JSON.parse(bytes);
const clear = fixture.alerts[0], ambiguous = fixture.alerts[8], normal = fixture.alerts[16];
const at = Date.parse(clear.timestamp);
async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-persistence-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('persistence projection preserves the official fixture and returns five redacted fields for all alerts', async () => {
  assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),
    '8dfb349b02cb0fd107a751c148be6165aa8c2725');
  const rows = await readAlerts();
  assert.equal(rows.length, 24);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'account,description,level,sourceIp,timestamp'));
  const secret = ['sb', 'secret', 'x'.repeat(1200)].join('_');
  const jwt = ['eyJ' + 'a'.repeat(1000), 'eyJ' + 'b'.repeat(1000), 'c'.repeat(1000)].join('.');
  const projected = JSON.stringify(projectAlerts([{ ...clear,
    data: { ...clear.data, srcuser: 'private' + '@example.invalid' },
    rule: { level: 12, description: `password="${secret}" Bearer ${jwt}\nextra` } }]));
  for (const value of [secret.slice(0, 100), jwt.slice(0, 100), 'private' + '@example.invalid']) {
    assert.equal(projected.includes(value), false);
  }
});

test('persistence catalog is grounded, decisions are stateless, and normal/ambiguous events are never blocks', async () => {
  const source = await readFile(new URL('xdr/persistence/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/persistence/patterns.json', root), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns);
  assert.ok(patterns.every(p => p.evidence && p.source.startsWith('https://attack.mitre.org/')));
  assert.doesNotMatch(source, /\bimport\s*(?:\(|[{'"*])/u);
  assert.doesNotMatch(source, /\b(?:fetch|eval|Function|readFile|writeFile)\s*\(/u);
  const before = JSON.stringify(fixture);
  const answers = fixture.alerts.map(decide);
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
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
  assert.ok(answers.slice(8, 16).every(out => out.action === 'alert'));
  assert.ok(answers.slice(16).every(out => out.action === 'record'));
});

test('unseen identities, filenames and equivalent service/task/startup evidence retain detection', () => {
  const event = (description, technique, path) => ({ id: 'unseen-event',
    rule: { level: 12, description, mitre: { id: [technique] } },
    data: { srcip: '2001:db8::24', srcuser: 'another-account', path } });
  const cases = [
    ['New unsigned service created with a replaced executable', 'T1543.003', 'C:\\Users\\other\\AppData\\Local\\Temp\\different.EXE', 'suspicious_service_persistence'],
    ['기존 서비스 실행 파일이 바뀌었고 서명이 없습니다.', 'T1543', 'C:\\Windows\\Temp\\other-service.exe', 'suspicious_service_persistence'],
    ['Unknown scheduled task executes outside normal hours', 'T1053.005', 'C:\\Users\\other\\AppData\\Local\\Temp\\new-task.cmd', 'suspicious_scheduled_task'],
    ['Unknown program added to startup folder; not in baseline', 'T1547.001', 'C:\\Users\\other\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\new-program.exe', 'unknown_startup_program'],
    ['새 미서명 서비스가 등록되었습니다.', 'T1543', 'C:\\Windows\\Temp\\other-service.exe', 'suspicious_service_persistence'],
    ['New unsigned systemd service created', 'T1543.002', '/tmp/new-agent', 'suspicious_service_persistence'],
  ];
  for (const [description, technique, path, pattern] of cases) {
    const out = decide(event(description, technique, path));
    assert.equal(out.action, 'block');
    assert.ok(out.reason.startsWith(pattern + ':'));
    assert.equal(out.reason.includes('other'), false);
  }
  const changed = { ...clear, id: 'other-id', timestamp: '2026-10-01T00:00:00Z',
    data: { srcip: '198.51.100.98', srcuser: 'other-account', path: 'C:\\Windows\\Temp\\new-name.exe' } };
  assert.deepEqual(decide(changed), decide(clear));
});

test('weak, conflicting or absent mutation evidence never causes an automatic isolation', () => {
  const patch = (rule, data) => ({ ...clear, rule: { ...clear.rule, ...rule }, data: { ...clear.data, ...data } });
  for (const event of [patch({ level: 8 }, {}), patch({ mitre: [] }, {}), patch({}, { srcip: 'bad' }),
    patch({}, { path: 'C:\\lab\\normal.exe' }),
    patch({ description: '서비스 서명은 확인되지 않았습니다. 새로 등록됐습니다.' }, {}),
    patch({ description: '서명된 서비스가 기존 파일 그대로 실행됩니다.' }, {}),
    patch({ description: '임시 파일이 생겼지만 서비스 등록은 없습니다.' }, {}),
    patch({ description: '서비스 설명만 바뀌었습니다. 실행 파일은 그대로입니다.' }, {}),
    patch({ description: '서비스 목록을 읽기만 했습니다.' }, {}),
    patch({ description: 'Unsigned service with a valid signature was created.' }, {}),
  ]) assert.notEqual(decide(event).action, 'block');
  const repeated = patch({ description: 'Unsigned service registration repeated 3 events.' }, { path: '', count: '3' });
  assert.equal(decide(repeated).action, 'block');
  assert.equal(decide({ ...repeated, data: { ...repeated.data, count: '1' } }).action, 'alert');
  assert.equal(decide({ ...repeated, data: { ...repeated.data, count: '999' } }).action, 'alert');
  const justCount = patch({ description: '서비스가 실행 중입니다.' }, { count: '999' });
  assert.notEqual(decide(justCount).action, 'block');
  for (const event of [null, [], '', {}, { rule: { level: 16, mitre: ['T1543'] } }]) {
    assert.notEqual(decide(event).action, 'block');
  }
});

test('persistence decide runs alone in an empty VM with imports and Node globals unavailable', () => {
  const script = `
    const fs = require('node:fs'); const vm = require('node:vm');
    (async () => {
      const context = vm.createContext({});
      const mod = new vm.SourceTextModule(fs.readFileSync(process.argv[1], 'utf8'), { context });
      await mod.link(() => { throw new Error('imports_forbidden'); });
      await mod.evaluate({ timeout: 1000 }); context.call = mod.namespace.decide;
      const counts = { block: 0, alert: 0, record: 0 };
      for (const alert of JSON.parse(fs.readFileSync(process.argv[2], 'utf8')).alerts) {
        context.input = alert;
        counts[vm.runInContext('call(input)', context, { timeout: 1000 }).action]++;
      }
      process.stdout.write(JSON.stringify(counts));
    })().catch(() => { process.exitCode = 1; });`;
  const out = execFileSync(process.execPath, ['--experimental-vm-modules', '-e', script,
    new URL('xdr/persistence/decide.mjs', root).pathname, new URL('xdr/fixtures/persistence.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 8, alert: 8, record: 8 });
});

test('only fresh clear persistence events add expiring rules; repeat delivery does not extend them', async t => {
  const paths = await temporary(t);
  for (const alert of [ambiguous, normal]) {
    assert.equal((await respond(alert, { ...paths, now: Date.parse(alert.timestamp) })).addedRule, null);
  }
  assert.equal((await respond(clear, { ...paths, now: at - 1 })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at + 6 * 60 * 1000 })).addedRule, null);
  const secret = ['sb', 'secret', 'x'.repeat(24)].join('_');
  const enriched = { ...clear, full_log: secret, data: { ...clear.data, password: secret } };
  const out = await respond(enriched, { ...paths, now: at });
  assert.ok(out.addedRule);
  assert.deepEqual(out.addedRule.evidenceAlertIds, [clear.id]);
  assert.equal(Date.parse(out.addedRule.expiresAt), at + 15 * 60 * 1000);
  await respond(clear, { ...paths, now: at + 1000 });
  assert.equal(Date.parse((await findDenyRule(clear.data.srcip, { ...paths, now: at + 1000 })).expiresAt), at + 15 * 60 * 1000);
  const other = { ...clear, id: 'new-evidence', timestamp: new Date(at + 2000).toISOString() };
  await Promise.all([respond(clear, { ...paths, now: at + 2000 }), respond(other, { ...paths, now: at + 2000 })]);
  const merged = await findDenyRule(clear.data.srcip, { ...paths, now: at + 3000 });
  assert.deepEqual(new Set(merged.evidenceAlertIds), new Set([clear.id, other.id]));
  assert.equal(await findDenyRule(clear.data.srcip, { ...paths, now: Date.parse(merged.expiresAt) }), null);
  const log = await readFile(paths.logPath, 'utf8');
  for (const value of [secret, clear.rule.description, clear.data.path, clear.data.srcuser]) assert.equal(log.includes(value), false);
});

test('persistence gate adds denial only for a server-confirmed source and preserves existing policy', async t => {
  const paths = await temporary(t); await respond(clear, { ...paths, now: at });
  const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'test-request', sourceIp: clear.data.srcip });
  const verdict = Object.freeze({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'step_up', reasonCode: 'fixture_step_up', ruleIds: ['fixture.base'] });
  const base = seen => { assert.equal(seen, request); return verdict; };
  const options = { rulePath: paths.rulePath, clock: () => at,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }) };
  for (const source of [normal.data.srcip, null]) {
    assert.equal(await createXdrGate(base, { ...options, trustedSourceIpForRequest: () => source })(request), verdict);
  }
  assert.equal((await createXdrGate(base, { ...options, trustedSourceIpForRequest: () => clear.data.srcip })(request)).decision, 'deny');
  const actual = createVaultXdrGate({ ...options, trustedSourceIpForRequest: () => normal.data.srcip });
  assert.deepEqual(await actual(request), await originalDecide(request));
  assert.throws(() => createXdrGate(base), /trusted_xdr_gate_callbacks_required/u);
});

test('chronological persistence replay isolates 8 candidates and passes all 8 normal fixture requests', async t => {
  const report = await replayPersistence({ root, ...await temporary(t) });
  assert.deepEqual(report.counts, { block: 8, alert: 8, record: 8 });
  assert.equal(report.rulesAdded, 8);
  assert.equal(report.blockedCandidatesDenied, 8);
  assert.equal(report.normalEvents, 8);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});
