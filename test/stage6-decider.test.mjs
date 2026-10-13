import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const normal = fixtureRequests().normal;
test('stage 6 allows only registered note reads and preserves the five-field response', async () => {
  const before = JSON.stringify(normal);
  for (const base of ['/notes', '/api/notes']) {
    for (const [route, path] of [[`GET ${base}`, base], [`GET ${base}/:id`, `${base}/11111111-1111-4111-8111-111111111111`]]) {
      const out = await decide({ ...normal, route, path });
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
