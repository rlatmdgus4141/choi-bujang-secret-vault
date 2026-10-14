import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const normal = fixtureRequests().normal;
test('stage 6 allows only registered note reads and preserves the five-field response', async () => {
  const before = JSON.stringify(normal);
  for (const base of ['/notes', '/api/notes']) {
    for (const [route, path] of [[`GET ${base}/:id`, `${base}/11111111-1111-4111-8111-111111111111`]]) {
      const request = { ...normal, route, path };
      const out = await decide(request);
      assert.deepEqual(out, { schema: 'aleph.decision.v1', requestId: normal.requestId,
        decision: 'allow', reasonCode: 'approved', ruleIds: ['resource_zones'] });
    }
  }
  assert.equal(JSON.stringify(normal), before);
  assert.ok(RULE_IDS.includes('device_registered'));
});
test('stage 6 denies missing, false and forged truthy registration flags', async () => {
  for (const flag of [false, undefined, null, 'true', 'false', 1, {}, []]) {
    const out = await decide({ ...normal, deviceRegistered: flag });
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'device_not_registered');
    assert.deepEqual(out.ruleIds, ['device_registered']);
  }
  const missing = { ...normal }; delete missing.deviceRegistered;
  assert.equal((await decide(missing)).reasonCode, 'device_not_registered');
});
test('stage 6 does not grant other services, mutations, unverified identities or mismatched routes', async () => {
  for (const change of [{ service: 'admin' }, { method: 'POST' }, { method: 'PUT' }, { method: 'DELETE' },
    { subjectId: '' }, { deviceId: '' }, { schema: 'invalid' }, { path: '/notes/../admin' },
    { route: 'GET /admin' }, { path: '/notes/a/b' }]) {
    const out = await decide({ ...normal, ...change });
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'starter_not_ready');
  }
});

test('stage 6 bonus reads only documented fields and returns valid allow, deny and step_up responses', async () => {
  const doc = readFileSync(new URL('../docs/DECIDER_REQUEST.md', import.meta.url), 'utf8');
  const table = doc.split('## 요청')[1].split('## 응답')[0].split('\n').filter(line => line.startsWith('|'));
  const fields = new Set(table.flatMap(line => [...line.split('|')[1].matchAll(/`([A-Za-z][A-Za-z0-9]*)`/gu)].map(match => match[1])));
  assert.equal(fields.size, 18);
  const guard = (value, allowed) => new Proxy(value, {
    get(target, key) {
      assert.ok(typeof key === 'string' && allowed.has(key), `undocumented request field: ${String(key)}`);
      return target[key];
    },
    set() { throw new Error('request mutation'); },
    deleteProperty() { throw new Error('request mutation'); },
  });
  const { suspicious } = fixtureRequests();
  const cases = [normal, suspicious, { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } },
    ...[false, undefined, null, 'true', 1].map(deviceRegistered => ({ ...normal, deviceRegistered })),
    { ...normal, subjectId: '' }, { ...normal, deviceId: '' }, { ...normal, schema: 'invalid' },
    { ...normal, queryLength: 1 }, { ...normal, route: 'GET /admin' },
    { ...normal, signals: null }, { ...normal, recentEvents: [null] },
    { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null } }];
  const decisions = new Set();
  for (const input of cases) {
    const source = structuredClone(input);
    const before = JSON.stringify(source);
    const request = { ...source,
      signals: source.signals && guard(source.signals, new Set(['source', 'region', 'network', 'hour'])),
      stepUp: source.stepUp && guard(source.stepUp, new Set(['verified', 'authAgeSeconds'])),
      recentEvents: source.recentEvents && Object.freeze(source.recentEvents.map(event => event
        && guard(event, new Set(['kind', 'ageSeconds', 'count'])))) };
    const response = await decide(guard(request, fields));
    assert.equal(Object.keys(response).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
    assert.equal(response.schema, 'aleph.decision.v1');
    assert.equal(response.requestId, source.requestId);
    assert.ok(['allow', 'deny', 'step_up'].includes(response.decision));
    assert.match(response.reasonCode, /^[a-z][a-z0-9_]{0,63}$/u);
    assert.ok(Array.isArray(response.ruleIds) && response.ruleIds.length > 0
      && response.ruleIds.every(id => RULE_IDS.includes(id)));
    assert.equal(JSON.stringify(source), before);
    decisions.add(response.decision);
  }
  assert.deepEqual([...decisions].sort(), ['allow', 'deny', 'step_up']);
});
