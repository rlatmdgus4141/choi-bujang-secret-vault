import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
const { normal, suspicious } = fixtureRequests();
const ids = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
const item = (base, method, id = ids[0]) => ({ ...normal,
  service: base.endsWith('notices') ? 'notices' : 'notes', method,
  path: `${base}/${id}`, route: `${method} ${base}/:id` });

test('stage 8 admits new engine-verified identities and individual note routes; ownership is checked by the API', async () => {
  for (const base of ['/notes', '/api/notes']) for (const method of ['GET','PUT','DELETE']) {
    for (const i of [0,1]) {
      const request = { ...item(base, method, ids[i]), classId: 'new_class', projectId: 'new_project',
        subjectId: `verified_subject_${i}`, deviceId: (i ? 'b' : 'a').repeat(16) };
      assert.equal((await decide(request)).decision, 'allow');
    }
  }
  for (const base of ['/notes', '/api/notes']) {
    assert.equal((await decide({ ...normal, method: 'POST', path: base, route: `POST ${base}` })).decision, 'allow');
  }
  assert.equal((await decide(normal)).decision, 'allow');
});

test('stage 8 denies every unscoped note list even with fresh login, a role claim or a supplied grant', async () => {
  for (const base of ['/notes', '/api/notes']) for (const subjectId of ['verified_A','verified_B']) {
    const request = { ...normal, subjectId, path: base, route: `GET ${base}`,
      stepUp: { verified: true, authAgeSeconds: 0 }, role: 'instructor',
      grants: [{ subjectId, method: 'GET', path: base }], headers: { 'x-role': 'instructor' } };
    const out = await decide(request);
    assert.equal(out.decision, 'deny');
    assert.deepEqual(out.ruleIds, ['resource_zones']);
  }
});

test('stage 8 denies all notice/instructor writes because the engine request contract supplies no role', async () => {
  for (const service of ['notices','announcements','instructor']) {
    for (const method of ['POST','PUT','PATCH','DELETE']) {
      for (const base of [`/${service}`, `/api/${service}`]) for (const path of [base, `${base}/${ids[0]}`]) {
        const request = { ...normal, service, method, path,
          route: `${method} ${path === base ? base : base + '/:id'}`,
          subjectId: 'verified_instructor_claim', role: 'instructor',
          stepUp: { verified: true, authAgeSeconds: 0 } };
        assert.equal((await decide(request)).decision, 'deny');
      }
    }
  }
});

test('stage 8 permits exact shared notice reads and denies unknown services and method/route mismatches', async () => {
  for (const base of ['/notices', '/api/notices']) {
    assert.equal((await decide({ ...normal, service: 'notices', path: base, route: `GET ${base}` })).decision, 'allow');
    assert.equal((await decide(item(base, 'GET'))).decision, 'allow');
  }
  const request = item('/notes', 'GET');
  for (const patch of [{ service: 'admin' }, { service: 'notices' }, { method: 'PUT' },
    { route: 'GET /api/notes/:id' }, { route: 'GET /notes/*' }, { path: '/other/' + ids[0] },
    { method: 'PATCH', route: 'PATCH /notes/:id' }]) {
    assert.equal((await decide({ ...request, ...patch })).decision, 'deny');
  }
});

test('stage 8 does not confuse reserved feature endpoints, nested or encoded paths with resource IDs', async () => {
  for (const base of ['/notes', '/api/notes', '/notices', '/api/notices']) {
    for (const id of ['export','EXPORT','list','all','search','bulk','download','admin','notices','announcements','instructor',
      '..','%2e%2e','id/extra','id?export=true','id#export','id\\other','']) {
      assert.equal((await decide(item(base, 'GET', id))).decision, 'deny', `${base}/${id}`);
    }
  }
});

test('stage 8 requires supplied identity/device fields and never authorizes a hidden query selector', async () => {
  const request = item('/notes', 'GET');
  for (const queryLength of [1, -1, undefined, null, '0']) {
    assert.equal((await decide({ ...request, queryLength })).decision, 'deny');
  }
  for (const key of ['classId','projectId','subjectId','deviceId']) {
    for (const value of [undefined, '', '*', {}, 'unverified value']) {
      assert.equal((await decide({ ...request, [key]: value })).decision, 'deny');
    }
  }
});

test('stage 8 keeps device and compound-risk checks; fresh login cannot authorize a prohibited zone', async () => {
  const request = { ...suspicious, ...item('/notes', 'PUT'), signals: suspicious.signals,
    recentEvents: suspicious.recentEvents };
  assert.equal((await decide(request)).decision, 'step_up');
  assert.equal((await decide({ ...request, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
  assert.equal((await decide({ ...request, stepUp: { verified: true, authAgeSeconds: 901 } })).decision, 'step_up');
  assert.equal((await decide({ ...request, deviceRegistered: false })).reasonCode, 'device_not_registered');
  for (const route of [{ service: 'notes', path: '/notes', route: 'GET /notes', method: 'GET' },
    { service: 'notices', path: '/notices', route: 'POST /notices', method: 'POST' }]) {
    assert.equal((await decide({ ...request, ...route, stepUp: { verified: true, authAgeSeconds: 0 } })).decision, 'deny');
  }
});

test('stage 8 keeps the five-field response and does not mutate the verified engine request', async () => {
  for (const request of [normal, item('/notes','PUT'), { ...normal, path: '/notes', route: 'GET /notes' }]) {
    const before = JSON.stringify(request);
    const out = await decide(request);
    assert.equal(JSON.stringify(request), before);
    assert.equal(Object.keys(out).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
    assert.equal(out.requestId, request.requestId);
    assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)));
    assert.ok(['approved','starter_not_ready','step_up_required','device_not_registered'].includes(out.reasonCode));
  }
});
