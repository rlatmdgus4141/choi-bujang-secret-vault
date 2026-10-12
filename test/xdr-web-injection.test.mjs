import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { decide } from '../xdr/web-injection/decide.mjs';
import { readAlerts, projectAlerts } from '../xdr/web-injection/read-alerts.mjs';
import { respond, findDenyRule, createXdrGate, createVaultXdrGate } from '../xdr/web-injection/respond.mjs';
import { decide as originalDecide } from '../src/decider.mjs';
import { replayWebInjection } from '../scripts/xdr-web-replay.mjs';

const root = new URL('../', import.meta.url);
const rawFixture = await readFile(new URL('xdr/fixtures/web-injection.json', root));
const fixture = JSON.parse(rawFixture);
const clear = fixture.alerts[0];
const ambiguous = fixture.alerts[8];
const normal = fixture.alerts[17];
const at = Date.parse(clear.timestamp);

async function temporary(t) {
  const dir = await mkdtemp(join(tmpdir(), 'aleph-xdr-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return { rulePath: join(dir, 'rules.json'), logPath: join(dir, 'alerts.log') };
}

test('official fixture stays unchanged; projection has exactly five sanitized fields for all alerts', async () => {
  const header = Buffer.from(`blob ${rawFixture.length}\0`);
  const blob = createHash('sha1').update(header).update(rawFixture).digest('hex');
  assert.equal(blob, 'c1e6b7f2d226c5f85e09e026f726fdcb8fd7eff1');
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
  const source = await readFile(new URL('xdr/web-injection/decide.mjs', root), 'utf8');
  const patterns = JSON.parse(await readFile(new URL('xdr/web-injection/patterns.json', root), 'utf8'));
  assert.deepEqual(JSON.parse(source.match(/const PATTERNS = (\[[\s\S]*?\]);/u)[1]), patterns);
  assert.ok(patterns.every(p => p.evidence && /^https:\/\/(?:attack\.mitre\.org|owasp\.org)\//u.test(p.source)));
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
  assert.deepEqual(counts, { block: 8, alert: 9, record: 9 });
});

test('single requests, mismatched counts, weak correlation, malformed sources and long windows never auto-block', () => {
  const changed = (rule, data) => ({ ...clear, rule: { ...clear.rule, ...rule }, data: { ...clear.data, ...data } });
  for (const entry of [
    changed({}, { count: '1' }), changed({}, { count: '999' }),
    changed({ mitre: [] }, {}), changed({ level: 8 }, {}),
    changed({}, { srcip: '999.1.1.1' }), changed({}, { srcip: ':1:2:3:4:5:6:7:8' }),
    changed({}, { url: '' }), changed({}, { window_seconds: 86400 }),
    changed({}, { window_seconds: 'invalid' }),
    changed({ description: 'SQL 구문이 같은 주소에서 12번, 24시간 동안 반복됐습니다.' }, {}),
    changed({ description: 'SQL 주입 12건. 반복은 없습니다.' }, {}),
  ]) assert.notEqual(decide(entry).action, 'block');
  for (const value of [null, [], '', {}, { rule: { level: 16, mitre: ['T1190'] } }]) {
    assert.notEqual(decide(value).action, 'block');
  }
  const negative = changed({ description: 'SQL 구문 표기는 없습니다. 정상 조회입니다.' }, {});
  assert.notEqual(decide(negative).action, 'block');
  const boundary = changed({ description: '같은 주소에서 SQL 주입이 5번 반복됐습니다.' }, { count: '5' });
  assert.equal(decide(boundary).action, 'block');
  assert.equal(decide(changed({ description: '같은 주소에서 SQL 주입이 4번 반복됐습니다.' }, { count: '4' })).action, 'alert');
});

test('raw and encoded request patterns work without fixture identifiers or placeholder strings', () => {
  const event = url => ({ id: 'other-id', rule: { level: 12, mitre: { id: ['T1190'] }, description: 'Repeated requests from the same source' },
    data: { srcip: '2001:db8::23', url, count: 8, window_seconds: 60 } });
  for (const [query, pattern] of [
    ['1 UNION SELECT 1', 'sql_injection'], ["1 OR 1=1", 'sql_injection'],
    ['<script>void(0)</script>', 'script_injection'], ['<img src=x onerror="void(0)">', 'script_injection'],
    ['../../fixture.txt', 'path_traversal'], ['demo;whoami', 'command_injection'],
  ]) {
    for (const value of [query, encodeURIComponent(query), encodeURIComponent(encodeURIComponent(query))]) {
      const answer = decide(event('/search?q=' + value));
      assert.equal(answer.action, 'block');
      assert.ok(answer.reason.startsWith(pattern + ':'));
      assert.equal(decide({ ...event('/search?q=' + value), data: { ...event('').data, url: '/search?q=' + value, count: 1 } }).action, 'alert');
    }
  }
  // A frequent normal search for course names or punctuation is not an attack signature.
  for (const value of ['select-course', 'script-class', 'up-notes', "O'Reilly", 'hello;world', 'SQL class']) {
    assert.notEqual(decide(event('/search?q=' + value)).action, 'block');
  }
  const modified = { ...clear, id: 'unseen-event', data: { ...clear.data, url: '/different?q=redacted', srcip: '198.51.100.99' } };
  assert.deepEqual(decide(modified), decide(clear));
  assert.doesNotThrow(() => decide(event('/search?q=%ZZ' + 'a'.repeat(20000))));
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
    new URL('xdr/web-injection/decide.mjs', root).pathname, new URL('xdr/fixtures/web-injection.json', root).pathname],
  { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  assert.deepEqual(JSON.parse(out), { block: 8, alert: 9, record: 9 });
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
  const report = await replayWebInjection({ root, ...paths });
  assert.deepEqual(report.counts, { block: 8, alert: 9, record: 9 });
  assert.equal(report.rulesAdded, 8);
  assert.equal(report.blockedCandidatesDenied, 8);
  assert.equal(report.normalEvents, 9);
  assert.equal(report.normalBlocked, 0);
  assert.equal(report.liveEngineConnected, false);
});
