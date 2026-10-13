import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
const normal = fixtureRequests().normal;

test('stage 8 gates exact note CRUD routes and read-only notices without changing the engine contract', async () => {
  for (const base of ['/notes', '/api/notes']) {
    for (const [method, path, route] of [
      ['GET', base, base], ['POST', base, base],
      ...['GET', 'PUT', 'DELETE'].map(method => [method, `${base}/note-id`, `${base}/:id`]),
    ]) {
      const out = await decide({ ...normal, method, path, route: `${method} ${route}` });
      assert.equal(out.decision, 'allow');
      assert.deepEqual(out.ruleIds, ['resource_zones']);
      assert.equal(Object.keys(out).length, 5);
    }
  }
  for (const base of ['/notices', '/api/notices']) {
    assert.equal((await decide({ ...normal, service: 'notices', path: base, route: `GET ${base}` })).decision, 'allow');
    for (const method of ['POST', 'PUT', 'DELETE']) {
      assert.equal((await decide({ ...normal, service: 'notices', method,
        path: `${base}/notice-id`, route: `${method} ${base}/:id`, role: 'instructor' })).decision, 'deny');
    }
  }
  assert.ok(RULE_IDS.includes('resource_zones'));
});

test('unknown paths, reserved operations, nested/encoded paths, service mismatch and query selectors cannot pass', async () => {
  for (const path of ['/notes/export', '/notes/EXPORT', '/notes/bulk', '/notes/a/b',
    '/notes/../notices', '/notes/%2e%2e', '/notes/a%2fb', '/notes/a?role=admin', '/notes/', '/admin']) {
    assert.equal((await decide({ ...normal, path })).decision, 'deny', path);
  }
  for (const patch of [{ service: 'notices' }, { route: 'PUT /notes/:id' },
    { queryLength: 1 }, { queryLength: undefined }, { deviceRegistered: false }]) {
    assert.equal((await decide({ ...normal, ...patch })).decision, 'deny');
  }
});
