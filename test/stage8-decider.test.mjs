import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, createDecider, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
const { normal, suspicious } = fixtureRequests();
const fields = ['classId','projectId','subjectId','deviceId','service','method','path','route'];
const grantFor = request => Object.fromEntries(fields.map(key => [key, request[key]]));
const ids = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'];
const own = i => ({ ...normal, subjectId: `configured_subject_${i}`, deviceId: (i ? 'b' : 'a').repeat(16),
  path: `/notes/${ids[i]}`, route: 'GET /notes/:id' });

test('UUID syntax and collection routes never grant access to an unenrolled resource', async () => {
  for (const base of ['/notes', '/api/notes']) for (const subjectId of [normal.subjectId, 'another_subject']) {
    for (const [method, path, route] of [
      ['GET', base, base], ['POST', base, base],
      ...['GET','PUT','DELETE'].map(method => [method, `${base}/${ids[0]}`, `${base}/:id`]),
    ]) {
      const out = await decide({ ...normal, subjectId, method, path, route: `${method} ${route}` });
      assert.equal(out.decision, 'deny');
      assert.deepEqual(out.ruleIds, ['resource_zones']);
    }
  }
  assert.equal((await createDecider()(normal)).decision, 'deny');
  assert.equal((await decide(normal)).decision, 'allow');
  assert.ok(RULE_IDS.includes('resource_zones'));
});

test('server-enrolled A and B each access own exact resource, never the other resource', async () => {
  const grants = [0,1].flatMap(i => ['GET','PUT','DELETE'].map(method =>
    grantFor({ ...own(i), method, route: `${method} /notes/:id` })));
  const policy = createDecider({ grants });
  for (const i of [0,1]) for (const method of ['GET','PUT','DELETE']) {
    const request = { ...own(i), method, route: `${method} /notes/:id` };
    assert.equal((await policy(request)).decision, 'allow');
    assert.equal((await policy({ ...request, path: own(1-i).path })).decision, 'deny');
  }
});

test('an explicit list or create grant authorizes only its bound subject and device', async () => {
  for (const method of ['GET','POST']) {
    const request = { ...own(0), method, path: '/api/notes', route: `${method} /api/notes` };
    const policy = createDecider({ grants: [grantFor(request)] });
    assert.equal((await policy(request)).decision, 'allow');
    assert.equal((await policy({ ...request, subjectId: own(1).subjectId })).decision, 'deny');
    assert.equal((await policy({ ...request, deviceId: own(1).deviceId })).decision, 'deny');
  }
});

test('instructor notice mutation requires an explicit trusted grant; student role claims do not grant it', async () => {
  const instructor = { ...own(0), subjectId: 'configured_instructor', service: 'notices',
    method: 'PUT', path: `/api/notices/${ids[0]}`, route: 'PUT /api/notices/:id' };
  const grants = [grantFor(instructor)];
  const policy = createDecider({ grants });
  assert.equal((await policy(instructor)).decision, 'allow');
  const student = { ...instructor, subjectId: own(1).subjectId, role: 'instructor',
    identity: { sub: instructor.subjectId }, headers: { 'x-role': 'instructor' },
    grants, policy: { grants }, owner_id: instructor.subjectId };
  assert.equal((await policy(student)).decision, 'deny');
  assert.equal((await decide({ ...instructor, grants })).decision, 'deny');
});

test('all scope and route fields match exactly; paths, aliases, selectors and fresh login cannot expand a grant', async () => {
  const request = own(0), policy = createDecider({ grants: [grantFor(request)] });
  for (const patch of [{ subjectId: own(1).subjectId }, { deviceId: own(1).deviceId },
    { classId: 'another_class' }, { projectId: 'another_project' }, { service: 'notices' },
    { method: 'PUT' }, { route: 'GET /api/notes/:id' }, { path: `/api/notes/${ids[0]}` },
    { path: '/notes/export' }, { path: `${request.path}/more` }, { path: '/notes/../admin' },
    { queryLength: 1 }, { queryLength: undefined }, { path: `/notes/${ids[1]}` }]) {
    assert.equal((await policy({ ...request, ...patch, stepUp: { verified: true, authAgeSeconds: 0 } })).decision, 'deny');
  }
  for (const key of fields) assert.equal((await policy({ ...request, [key]: undefined })).decision, 'deny');
});

test('server policy snapshots cannot be changed by later mutation or request-supplied permissions', async () => {
  const request = own(0), grant = grantFor(request), grants = [grant];
  const policy = createDecider({ grants });
  grant.subjectId = own(1).subjectId;
  grants.push(grantFor(own(1)));
  assert.equal((await policy(request)).decision, 'allow');
  assert.equal((await policy({ ...own(1), grants, policy: { grants } })).decision, 'deny');
  for (const invalid of [{ ...grantFor(request), subjectId: '*' },
    { ...grantFor(request), deviceId: '' }, { ...grantFor(request), route: 'GET /notes/*' },
    { ...grantFor(request), path: '/notes/export' }, { ...grantFor(request), path: '/notes/../admin' },
    { ...grantFor(request), role: 'instructor' }, { ...grantFor(request), method: 'PATCH' }]) {
    assert.throws(() => createDecider({ grants: [invalid] }), /Invalid resource grant/u);
  }
});

test('registration and compound-risk rules still apply after exact resource authorization', async () => {
  const request = { ...suspicious, ...grantFor(own(0)), method: 'PUT', route: 'PUT /notes/:id' };
  const policy = createDecider({ grants: [grantFor(request)] });
  assert.equal((await policy(request)).decision, 'step_up');
  assert.equal((await policy({ ...request, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'allow');
  assert.equal((await policy({ ...request, stepUp: { verified: true, authAgeSeconds: 901 } })).decision, 'step_up');
  assert.equal((await policy({ ...request, deviceRegistered: false })).reasonCode, 'device_not_registered');
  assert.equal((await policy({ ...request, subjectId: own(1).subjectId, stepUp: { verified: true, authAgeSeconds: 60 } })).decision, 'deny');
});

test('documented exercise grant does not admit other subjects, scopes, devices or live demo requests', async () => {
  assert.equal((await decide(normal)).decision, 'allow');
  for (const [key,value] of Object.entries({ subjectId: 'another_subject', deviceId: 'b'.repeat(16),
    classId: 'another_class', projectId: 'another_project' })) {
    assert.equal((await decide({ ...normal, [key]: value })).decision, 'deny');
  }
  assert.equal((await decide({ ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null } })).decision, 'deny');
});
