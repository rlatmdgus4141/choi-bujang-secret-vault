import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { projectAlerts, readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { respond, findDenyRule, createXdrGate, createVaultXdrGate } from '../xdr/exfiltration/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayExfiltration } from '../scripts/xdr-exfiltration-replay.mjs';

const root = new URL('../', import.meta.url);
const bytes = await readFile(new URL('xdr/fixtures/exfiltration.json', root));
const fixture = JSON.parse(bytes);
const clear = fixture.alerts[0], ambiguous = fixture.alerts[10], normal = fixture.alerts[20];
const at = Date.parse(clear.timestamp);
async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-exfiltration-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('exfiltration projection preserves the official fixture and returns five redacted fields for all alerts', async () => {
  assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),
    'ccd294ff72eade41f13c350d69b05a42c346ba40');
  const rows = await readAlerts();
  assert.equal(rows.length, 30);
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

test('exfiltration catalog is grounded, decisions are stateless, and normal/ambiguous events are never blocks', async () => {
  const source = await readFile(new URL('xdr/exfiltration/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/exfiltration/patterns.json', root), 'utf8'));
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
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
  assert.ok(answers.slice(10, 20).every(out => out.action === 'alert'));
  assert.ok(answers.slice(20).every(out => out.action === 'record'));
});

test('exfiltration decide runs alone in an empty VM with imports and Node globals unavailable', () => {
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
    new URL('xdr/exfiltration/decide.mjs', root).pathname, new URL('xdr/fixtures/exfiltration.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 10, alert: 10, record: 10 });
});

test('only fresh clear exfiltration events add expiring rules; repeat delivery does not extend them', async t => {
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
  assert.equal(Date.parse((await findDenyRule(clear.data.dstip, { ...paths, now: at + 1000 })).expiresAt), at + 15 * 60 * 1000);
  const other = { ...clear, id: 'new-evidence', timestamp: new Date(at + 2000).toISOString() };
  await Promise.all([respond(clear, { ...paths, now: at + 2000 }), respond(other, { ...paths, now: at + 2000 })]);
  const merged = await findDenyRule(clear.data.dstip, { ...paths, now: at + 3000 });
  assert.deepEqual(new Set(merged.evidenceAlertIds), new Set([clear.id, other.id]));
  assert.equal(await findDenyRule(clear.data.dstip, { ...paths, now: Date.parse(merged.expiresAt) }), null);
  const log = await readFile(paths.logPath, 'utf8');
  for (const value of [secret, clear.rule.description, clear.data.dstip, clear.data.srcuser]) assert.equal(log.includes(value), false);
});

test('exfiltration gate adds denial only for a server-confirmed destination and preserves existing policy', async t => {
  const paths = await temporary(t); await respond(clear, { ...paths, now: at });
  const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'test-request', destinationIp: clear.data.dstip });
  const verdict = Object.freeze({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'step_up', reasonCode: 'fixture_step_up', ruleIds: ['fixture.base'] });
  const base = seen => { assert.equal(seen, request); return verdict; };
  const options = { rulePath: paths.rulePath, clock: () => at,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }) };
  for (const destination of [normal.data.dstip, null]) {
    assert.equal(await createXdrGate(base, { ...options, trustedDestinationIpForRequest: () => destination })(request), verdict);
  }
  assert.equal((await createXdrGate(base, { ...options, trustedDestinationIpForRequest: () => clear.data.dstip })(request)).decision, 'deny');
  const actual = createVaultXdrGate({ ...options, trustedDestinationIpForRequest: () => normal.data.dstip });
  assert.deepEqual(await actual(request), await originalDecide(request));
  assert.throws(() => createXdrGate(base), /trusted_xdr_gate_callbacks_required/u);
});

test('chronological exfiltration replay denies 10 destinations and passes all 10 normal fixture requests', async t => {
  const report = await replayExfiltration({ root, ...await temporary(t) });
  assert.deepEqual(report.counts, { block: 10, alert: 10, record: 10 });
  assert.equal(report.rulesAdded, 10);
  assert.equal(report.blockedCandidatesDenied, 10);
  assert.equal(report.normalEvents, 10);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});

test('unseen destinations and equivalent English evidence are detected without matching fixture identities', () => {
  const event = (description, technique, metrics) => ({ id: 'unseen-event',
    rule: { level: 12, description, mitre: { id: [technique] } },
    data: { srcip: '2001:db8::10', srcuser: 'another-account', dstip: '2001:db8::24', bytes: '70000000', ...metrics } });
  const cases = [
    ['Large file transferred to a first-seen destination.', 'T1048.003', {}, 'large_transfer_to_new_destination'],
    ['Large transfer to same destination repeated 6 times.', 'T1041', { count: '6' }, 'repeated_large_external_transfer'],
    ['Compressed file transferred outside business hours.', 'T1048', { files: '1' }, 'off_hours_archive_or_repeated_transfer'],
    ['Unusual protocol: files transferred consecutively.', 'T1048', { files: '70' }, 'bulk_copy_or_unusual_protocol'],
    ['Entire dataset copied externally within a short period.', 'T1041', { files: '180' }, 'bulk_copy_or_unusual_protocol'],
  ];
  for (const [description, technique, metrics, pattern] of cases) {
    const out = decide(event(description, technique, metrics));
    assert.equal(out.action, 'block', description);
    assert.ok(out.reason.startsWith(pattern + ':'));
    assert.equal(out.reason.includes('another-account'), false);
  }
  assert.deepEqual(decide({ ...clear, id: 'changed-id', timestamp: '2026-10-01T00:00:00Z',
    data: { ...clear.data, srcip: '198.51.100.99', srcuser: 'other-account', dstip: '2001:db8::99' } }), decide(clear));
});

test('size alone, failed/no transfer, bad metrics and conflicting repetition never block', () => {
  const patch = (rule = {}, data = {}) => ({ ...clear, rule: { ...clear.rule, ...rule }, data: { ...clear.data, ...data } });
  for (const alert of [
    patch({}, { bytes: '49999999' }), patch({}, { bytes: '0' }), patch({}, { bytes: '-1' }),
    patch({}, { bytes: true }), patch({}, { bytes: Infinity }), patch({}, { bytes: '1000000000001' }),
    patch({}, { count: 'bad' }), patch({}, { dstip: '' }), patch({}, { dstip: '999.1.1.1' }),
    patch({ mitre: [] }), patch({ level: '9' }),
    patch({ description: '대용량 파일이 전송되었습니다. 평소 목적지입니다.' }),
    patch({ description: '처음 보는 주소로 전송을 시도했지만 실패했습니다.' }),
    patch({ description: '처음 보는 주소로 압축 파일을 준비했지만 외부 전송은 아직 없습니다.' }),
    patch({ description: '승인된 백업 전송: 처음 보는 주소로 큰 파일을 전송했습니다.' }),
    patch({ description: 'Large transfer to same destination repeated 8 times.' }, { count: '7' }),
    patch({ description: '자료실 전체가 외부로 복사됐습니다.' }), // No short-window evidence.
    patch({ description: 'New destination was not transferred: no external transfer.' }),
  ]) assert.notEqual(decide(alert).action, 'block');
  assert.equal(decide(patch({}, { bytes: '50000000' })).action, 'block');
  for (const input of [null, [], '', {}, { rule: { level: 16, mitre: ['T1048'] } }]) {
    assert.notEqual(decide(input).action, 'block');
  }
});

test('destination denial never quarantines the sender and does not trust request destination fields', async t => {
  const paths = await temporary(t);
  const out = await respond(clear, { ...paths, now: at });
  assert.equal(out.addedRule.destinationIp, clear.data.dstip);
  assert.equal(Object.hasOwn(out.addedRule, 'sourceIp'), false);
  assert.equal(await findDenyRule(clear.data.srcip, { ...paths, now: at }), null);
  const request = Object.freeze({ requestId: 'spoofed-destination', dstip: clear.data.dstip,
    headers: { 'x-destination-ip': clear.data.dstip } });
  const verdict = { schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'allow', reasonCode: 'fixture_allow', ruleIds: ['fixture.base'] };
  const base = seen => { assert.equal(seen, request); return verdict; };
  const options = { rulePath: paths.rulePath, clock: () => at,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }) };
  for (const target of [clear.data.srcip, normal.data.dstip, null]) {
    assert.equal(await createXdrGate(base, { ...options, trustedDestinationIpForRequest: () => target })(request), verdict);
  }
  assert.equal((await createXdrGate(base, { ...options,
    trustedDestinationIpForRequest: () => clear.data.dstip })(request)).decision, 'deny');
});
