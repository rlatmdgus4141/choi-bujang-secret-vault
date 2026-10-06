import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { generateKeyPair, SignJWT, jwtVerify, createLocalJWKSet, exportJWK } from 'jose';
import { createNotesHandler } from '../api/notes.js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import config from '../aleph.config.json' with { type: 'json' };

// 시험용 서명 키와 토큰은 실행 중 메모리에만 두며 실제 서비스에서는 사용하지 않습니다.
const pair = await generateKeyPair('ES256');
const wrongPair = await generateKeyPair('ES256');
const userId = '11111111-1111-4111-8111-111111111111';
const key = ['sb', 'secret', 'fixture'].join('_');
const env = { SUPABASE_URL: new URL(config.identityProvider.issuer).origin, SUPABASE_SECRET_KEY: key };
const now = () => Math.floor(Date.now() / 1000);
const claims = () => ({ iss: config.identityProvider.issuer, aud: 'authenticated',
  sub: userId, role: 'authenticated', iat: now(), exp: now() + 300 });
const token = (patch = {}, signingKey = pair.privateKey) => new SignJWT({ ...claims(), ...patch })
  .setProtectedHeader({ alg: 'ES256' }).sign(signingKey);
function response() {
  return { headers: {}, statusCode: 0, body: undefined,
    setHeader(name, value) { this.headers[name] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
}
function fixture({ failDb = false, claimPatch } = {}) {
  const calls = { reads: 0, claims: 0, clients: 0 };
  const clientFactory = (url, secret, options) => {
    calls.clients++;
    assert.equal(url, env.SUPABASE_URL);
    assert.equal(secret, key);
    assert.equal(options.auth.persistSession, false);
    return {
      auth: { async getClaims(value) {
        calls.claims++;
        try {
          const { payload } = await jwtVerify(value, pair.publicKey);
          return { data: { claims: { ...payload, ...claimPatch } }, error: null };
        } catch { return { data: null, error: new Error('fixture verification failed') }; }
      } },
      from(table) {
        calls.reads++;
        assert.equal(table, 'notes');
        return { select(fields) {
          assert.equal(fields, 'id,title,content');
          return { eq(column, value) {
            assert.equal(column, 'owner_id');
            assert.equal(value, userId);
            return this;
          }, async order(column) {
            assert.equal(column, 'position');
            return failDb ? { data: null, error: new Error(key) }
              : { data: [{ id: userId, title: 'fixture', content: 'test-only', extra: key }], error: null };
          } };
        } };
      },
    };
  };
  return { calls, handler: createNotesHandler({ env, clientFactory }) };
}
const request = (authorization, method = 'GET') => ({ method, headers: { authorization },
  body: { userId, role: 'authenticated' }, query: { userId, role: 'authenticated' } });

test('no login denies GET and POST before client or database use, ignoring submitted identity', async () => {
  const { calls, handler } = fixture();
  for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
    const res = response();
    await handler(request(undefined, method), res);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(Object.keys(res.body), ['error']);
    assert.equal(res.headers['Cache-Control'], 'no-store');
  }
  assert.deepEqual(calls, { reads: 0, claims: 0, clients: 0 });
});

test('valid signed student login reads only allowed fields and reuses the verifier', async () => {
  const { calls, handler } = fixture();
  const authorization = `Bearer ${await token()}`;
  for (let i = 0; i < 2; i++) {
    const res = response();
    await handler(request(authorization), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers.Vary, 'Authorization');
    assert.equal(res.body.length, 1);
    assert.deepEqual(Object.keys(res.body[0]).sort(), ['body', 'id', 'title']);
    assert.equal(JSON.stringify(res.body).includes(key), false);
  }
  assert.deepEqual(calls, { reads: 2, claims: 2, clients: 1 });
});

test('malformed, forged, expired, wrong audience, wrong issuer, role and subject tokens cannot read', async () => {
  const values = ['invalid', ['Bearer duplicate'], `Bearer ${await token({}, wrongPair.privateKey)}`,
    ...await Promise.all([
      { exp: now() - 30 }, { aud: 'another-service' }, { iss: 'https://another.supabase.co/auth/v1' },
      { role: 'anon' }, { sub: 'not-a-uuid' }, { exp: undefined },
    ].map(async patch => `Bearer ${await token(patch)}`))];
  const { calls, handler } = fixture();
  for (const value of values) {
    const res = response();
    await handler(request(value), res);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(Object.keys(res.body), ['error']);
  }
  assert.equal(calls.reads, 0);
});

test('helper checks expired claims even if the SDK were to return them', async () => {
  const { calls, handler } = fixture({ claimPatch: { exp: now() - 1 } });
  const res = response();
  await handler(request(`Bearer ${await token()}`), res);
  assert.equal(res.statusCode, 401);
  assert.equal(calls.reads, 0);
});

test('configuration errors, database failures and authenticated unsupported methods do not expose secrets', async () => {
  const authorization = `Bearer ${await token()}`;
  for (const badEnv of [{}, { ...env, SUPABASE_SECRET_KEY: 'client-key' },
    { ...env, SUPABASE_URL: 'https://another.supabase.co' }]) {
    const res = response();
    await createNotesHandler({ env: badEnv })(request(authorization), res);
    assert.equal(res.statusCode, 503);
  }
  const { handler } = fixture({ failDb: true });
  const res = response();
  await handler(request(authorization), res);
  assert.equal(res.statusCode, 502);
  assert.equal(JSON.stringify(res.body).includes(key), false);
  const post = response();
  await handler(request(authorization, 'PATCH'), post);
  assert.equal(post.statusCode, 405);
  assert.equal(post.headers.Allow, 'GET, POST');
});

test('unchanged helper validates signed judge identity and rejects expiry, forged signature and wrong service', async () => {
  const jwk = await exportJWK(pair.publicKey);
  const verify = createLoginVerifier({ config,
    judgeKeySet: createLocalJWKSet({ keys: [{ ...jwk, alg: 'ES256' }] }),
    supabaseClient: { auth: { getClaims() { throw new Error('wrong verification branch'); } } },
  });
  const judge = { ...claims(), iss: config.judgeIssuer,
    aud: new URL(config.publicAppUrl).hostname, aleph_role: 'judge',
    aleph_run: '22222222-2222-4222-8222-222222222222', aleph_identity: 'a' };
  const sign = (patch = {}, signer = pair.privateKey) => new SignJWT({ ...judge, ...patch })
    .setProtectedHeader({ alg: 'ES256' }).sign(signer);
  const identity = await verify(`Bearer ${await sign()}`);
  assert.equal(identity.userId, userId);
  assert.equal(identity.kind, 'judge');
  for (const patch of [{ aud: 'another.vercel.app' }, { exp: now() - 30, iat: now() - 60 },
    { aleph_identity: 'c' }, { aleph_role: 'student' }, { exp: now() + 1000 }]) {
    assert.equal(await verify(`Bearer ${await sign(patch)}`), null);
  }
  assert.equal(await verify(`Bearer ${await sign({}, wrongPair.privateKey)}`), null);
});

test('current deployment identity and unchanged starter verifier', async () => {
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github',
    VERCEL_GIT_REPO_OWNER: 'fixture', VERCEL_GIT_REPO_SLUG: 'vault',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'fixture.vercel.app' }, config);
  assert.equal(identity.step, 5);
  assert.equal(identity.originalApiUrl, config.originalApiUrl);
  assert.deepEqual(identity.allowedRoutes, config.allowedRoutes);
  const source = await readFile(new URL('../src/verify-login.mjs', import.meta.url));
  const gitBlob = createHash('sha1').update(`blob ${source.length}\0`).update(source).digest('hex');
  assert.equal(gitBlob, '784ec5af7067e01c6b7f83cf423db0b8c63d9e09');
});

test('authenticated stages self-check records actual rejection requests without token or note bodies', async () => {
  const original = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ path: new URL(url).pathname, search: new URL(url).search, options });
      if (new URL(url).pathname === '/rest/v1/notes') return Response.json({ code: '42501' }, { status: 401 });
      if (new URL(url).pathname === '/') return new Response('<script src="/auth.js"></script>', {
        headers: { 'X-Content-Type-Options': 'nosniff' } });
      if (new URL(url).pathname === '/auth.js') return new Response('server-auth');
      return new URL(url).pathname === '/data.json' ? Response.json({ notes: [] })
        : Response.json({ error: 'login required' }, { status: 401 });
    };
    const checks = await runAttackChecks(config);
    assert.equal(calls.length, 11);
    assert.equal(calls[2].options.method, 'POST');
    assert.ok(checks.slice(1, 9).every(check => check.observed.includes('HTTP 401')));
    assert.equal(JSON.stringify(checks).includes('Bearer'), false);
    assert.equal(JSON.stringify(checks).includes('sb_publishable_'), false);
    assert.ok(calls.slice(7, 9).every(call => call.options.headers.apikey.startsWith('sb_publishable_')
      && !call.options.headers.Authorization));
    assert.equal(calls[8].options.method, 'PATCH');
    assert.equal(calls[8].search, '?id=is.null');
    globalThis.fetch = async () => Response.json({ notes: ['fixture'] });
    const failed = await runAttackChecks(config);
    assert.ok(failed.every(check => check.observed.includes('확인 실패')));
  } finally { globalThis.fetch = original; }
});

function crudFixture() {
  const rows = new Map();
  const clientFactory = () => ({
    auth: { async getClaims(value) {
      try { return { data: { claims: (await jwtVerify(value, pair.publicKey)).payload }, error: null }; }
      catch { return { data: null, error: new Error('invalid fixture') }; }
    } },
    from() {
      let action = 'read'; let input; let fields; const filters = [];
      const execute = () => {
        const matched = [...rows.values()].filter(row => filters.every(([k, v]) => row[k] === v));
        let data = matched;
        if (action === 'insert') {
          if (rows.has(input.id)) return { data: null, error: { code: '23505' } };
          const row = { ...input, position: rows.size + 1 };
          rows.set(row.id, row); data = [row];
        }
        if (action === 'update') data = matched.map(row => {
          const changed = { ...row, ...input }; rows.set(row.id, changed); return changed;
        });
        if (action === 'delete') matched.forEach(row => rows.delete(row.id));
        return { data: data.map(row => Object.fromEntries(fields.split(',').map(field => [field, row[field]]))), error: null };
      };
      const builder = {
        select(value) { fields = value; return this; },
        insert(value) { action = 'insert'; input = value; return this; },
        update(value) { action = 'update'; input = value; return this; },
        delete() { action = 'delete'; return this; },
        eq(k, v) { filters.push([k, v]); return this; },
        async order() { return execute(); },
        async maybeSingle() { const r = execute(); return { ...r, data: r.data?.[0] ?? null }; },
        async single() { return this.maybeSingle(); },
      };
      return builder;
    },
  });
  const root = createNotesHandler({ env, clientFactory });
  const item = createNotesHandler({ env, clientFactory, itemRoute: true });
  return { rows, async call(method, bearer, body, id, extras = {}) {
    const res = response();
    await (id === undefined ? root : item)({ method, headers: { authorization: bearer, ...extras.headers }, body,
      query: { ...(id === undefined ? {} : { id }), ...extras.query } }, res);
    return res;
  } };
}

test('A CRUD follows the contract, preserves verified ownership, and returns 404 after deletion', async () => {
  const { call, rows } = crudFixture();
  const bearer = `Bearer ${await token()}`;
  const input = { title: 'fixture', body: 'test-only', userId: 'untrusted', role: 'admin' };
  const created = await call('POST', bearer, input);
  assert.equal(created.statusCode, 201);
  const id = created.body.id;
  assert.match(id, /^[0-9a-f-]{36}$/u);
  assert.equal(rows.get(id).owner_id, userId);
  assert.deepEqual(Object.keys(created.body), ['id']);
  const list = await call('GET', bearer);
  assert.deepEqual(list.body, [{ id, title: input.title, body: input.body }]);
  assert.deepEqual((await call('GET', bearer, undefined, id)).body, list.body[0]);
  const edited = await call('PUT', bearer, { title: 'updated', body: 'changed' }, id);
  assert.equal(edited.statusCode, 200);
  assert.equal(edited.body.body, 'changed');
  assert.equal(rows.get(id).owner_id, userId);
  assert.equal((await call('DELETE', bearer, undefined, id)).statusCode, 200);
  assert.equal((await call('GET', bearer, undefined, id)).statusCode, 404);
  assert.equal((await call('PUT', bearer, { title: 'gone', body: '' }, id)).statusCode, 404);
  assert.equal((await call('DELETE', bearer, undefined, id)).statusCode, 404);
});

test('explicit UUID works, duplicate insert cannot overwrite, and malformed input is rejected', async () => {
  const { call, rows } = crudFixture();
  const bearer = `Bearer ${await token()}`;
  const input = { id: '33333333-3333-4333-8333-333333333333', title: 'fixture', body: 'test-only' };
  assert.equal((await call('POST', bearer, input)).statusCode, 201);
  assert.equal((await call('POST', bearer, { ...input, title: 'overwrite' })).statusCode, 409);
  assert.equal(rows.get(input.id).title, input.title);
  for (const body of [null, [], '{', { ...input, id: 'bad' }, { ...input, title: ' ' },
    { ...input, body: 1 }, { ...input, body: 'x'.repeat(20001) }]) {
    assert.equal((await call('POST', bearer, body)).statusCode, 400);
  }
  assert.equal((await call('GET', bearer, undefined, 'bad-id')).statusCode, 400);
  assert.equal(rows.size, 1);
});

test('all item operations require authentication and B cannot read, update or delete A notes', async () => {
  const { call, rows } = crudFixture();
  const a = `Bearer ${await token()}`;
  const b = `Bearer ${await token({ sub: '22222222-2222-4222-8222-222222222222' })}`;
  const created = await call('POST', a, { title: 'fixture', body: 'test-only' });
  const id = created.body.id;
  for (const method of ['GET', 'PUT', 'DELETE']) {
    const res = await call(method, undefined, { title: 'untrusted', body: '' }, id);
    assert.equal(res.statusCode, 401);
    assert.deepEqual(Object.keys(res.body), ['error']);
  }
  assert.equal(rows.get(id).title, 'fixture');
  assert.deepEqual((await call('GET', b)).body, []);
  assert.equal((await call('GET', b, undefined, id)).statusCode, 404);
  assert.equal((await call('PUT', b, { title: 'B fixture', body: '' }, id)).statusCode, 404);
  assert.equal(rows.get(id).owner_id, userId);
  assert.equal((await call('DELETE', b, undefined, id)).statusCode, 404);
  assert.equal(rows.get(id).title, 'fixture');
  assert.equal((await call('GET', a, undefined, id)).statusCode, 200);
});

test('A and B each retain full CRUD while URL and header identity spoofing cannot cross owners', async () => {
  const { call, rows } = crudFixture();
  const bId = '22222222-2222-4222-8222-222222222222';
  const accounts = [
    { id: userId, bearer: `Bearer ${await token()}` },
    { id: bId, bearer: `Bearer ${await token({ sub: bId })}` },
  ];
  const ids = [];
  for (const account of accounts) {
    const created = await call('POST', account.bearer, { title: 'own fixture', body: 'test-only' });
    assert.equal(created.statusCode, 201);
    ids.push(created.body.id);
    assert.equal(rows.get(created.body.id).owner_id, account.id);
  }
  for (let i = 0; i < accounts.length; i++) {
    const self = accounts[i]; const other = accounts[1 - i]; const ownId = ids[i]; const otherId = ids[1 - i];
    const spoof = { query: { owner_id: other.id, userId: other.id, role: 'admin' },
      headers: { 'x-user-id': other.id, 'x-role': 'admin' } };
    const list = await call('GET', self.bearer, undefined, undefined, spoof);
    assert.deepEqual(list.body.map(row => row.id), [ownId]);
    assert.equal((await call('GET', self.bearer, undefined, ownId)).statusCode, 200);
    assert.equal((await call('PUT', self.bearer, { title: 'updated own', body: 'changed' }, ownId)).statusCode, 200);
    for (const method of ['GET', 'PUT', 'DELETE']) {
      const denied = await call(method, self.bearer, { title: 'tampered', body: '' }, otherId, spoof);
      assert.equal(denied.statusCode, 404);
      assert.deepEqual(Object.keys(denied.body), ['error']);
    }
  }
  for (let i = 0; i < accounts.length; i++) {
    assert.equal((await call('DELETE', accounts[i].bearer, undefined, ids[i])).statusCode, 200);
    assert.equal((await call('GET', accounts[i].bearer, undefined, ids[i])).statusCode, 404);
  }
});

test('POST and PUT reject supplied ownership transfer without creating or changing rows', async () => {
  const { call, rows } = crudFixture();
  const bearer = `Bearer ${await token()}`;
  const input = { title: 'fixture', body: 'test-only' };
  const created = await call('POST', bearer, input);
  const id = created.body.id;
  for (const forged of ['22222222-2222-4222-8222-222222222222', null, '', ['untrusted']]) {
    assert.equal((await call('POST', bearer, { ...input, owner_id: forged })).statusCode, 403);
    assert.equal((await call('PUT', bearer, { title: 'changed', body: '', owner_id: forged }, id)).statusCode, 403);
    assert.equal(rows.size, 1);
    assert.equal(rows.get(id).title, input.title);
    assert.equal(rows.get(id).owner_id, userId);
  }
  assert.equal((await call('PUT', bearer, { ...input, owner_id: userId }, id)).statusCode, 200);
  assert.equal(rows.get(id).owner_id, userId);
});

test('student cannot access judge-owned or ownerless rows; missing ownership never grants access', async () => {
  const { call, rows } = crudFixture();
  const bearer = `Bearer ${await token()}`;
  const ids = ['44444444-4444-4444-8444-444444444444', '55555555-5555-4555-8555-555555555555'];
  for (let i = 0; i < ids.length; i++) rows.set(ids[i], { id: ids[i], title: 'restricted fixture',
    content: 'test-only', owner_id: i === 0 ? '66666666-6666-4666-8666-666666666666' : null });
  assert.deepEqual((await call('GET', bearer)).body, []);
  for (const id of ids) for (const method of ['GET', 'PUT', 'DELETE']) {
    const denied = await call(method, bearer, { title: 'tampered', body: '' }, id);
    assert.equal(denied.statusCode, 404);
    assert.deepEqual(Object.keys(denied.body), ['error']);
    assert.equal(rows.get(id).title, 'restricted fixture');
  }
  assert.equal(rows.size, 2);
});
