import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
const normal = fixtureRequests().normal;

test('stage 8 gates exact note CRUD routes and read-only notices without changing the engine contract', async () => {
  for (const base of ['/notes', '/api/notes']) {
    for (const [method, path, route] of [
      ['GET', base, base], ['POST', base, base],
      ...['GET', 'PUT', 'DELETE'].map(method => [method, `${base}/11111111-1111-4111-8111-111111111111`, `${base}/:id`]),
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


test('stage 8 rejects every non-UUID live resource, including other-zone and notice-like slugs', async () => {
  const ids = ['other-user', 'another-zone', 'teacher-notice', 'notice-id', 'note-id',
    'random-resource', '11111111-1111-4111-8111-11111111111z'];
  for (const base of ['/notes', '/api/notes']) for (const id of ids) {
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const result = await decide({ ...normal, method, path: `${base}/${id}`, route: `${method} ${base}/:id` });
      assert.equal(result.decision, 'deny', `${method} ${base}/${id}`);
    }
  }
  assert.equal((await decide(normal)).decision, 'allow');
  for (const method of ['PUT', 'DELETE']) {
    assert.equal((await decide({ ...normal, method, route: `${method} /notes/:id` })).decision, 'deny');
  }
  assert.equal((await decide({ ...normal, path: '/api/notes/demo', route: 'GET /api/notes/:id' })).decision, 'deny');
});


test('the documented demo resource grant is bound to its subject, device, class and project', async () => {
  assert.equal((await decide(normal)).decision, 'allow');
  for (const [key, value] of Object.entries({ subjectId: 'another_subject',
    deviceId: 'bbbbbbbbbbbbbbbb', classId: 'another_class', projectId: 'another_project' })) {
    for (const replacement of [value, undefined, '', null]) {
      const request = { ...normal, [key]: replacement,
        headers: { 'x-user-id': normal.subjectId, 'x-device-id': normal.deviceId },
        identity: { sub: normal.subjectId }, role: 'instructor',
        stepUp: { verified: true, authAgeSeconds: 0 } };
      assert.equal((await decide(request)).decision, 'deny', key);
    }
  }
  assert.equal((await decide({ ...normal, signals: {
    source: 'none', region: 'unknown', network: 'unknown', hour: null } })).decision, 'deny');
  // Repeated requests do not establish ownership or poison a mutable first-seen cache.
  for (let i = 0; i < 3; i++) {
    assert.equal((await decide({ ...normal, subjectId: 'another_subject' })).decision, 'deny');
    assert.equal((await decide(normal)).decision, 'allow');
  }
});
