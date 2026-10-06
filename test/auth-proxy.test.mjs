import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT } from 'jose';
import { createClient } from '@supabase/supabase-js';
import { createAuthHandler } from '../api/auth.js';
import config from '../aleph.config.json' with { type: 'json' };

const projectUrl = new URL(config.identityProvider.issuer).origin;
const env = { SUPABASE_URL: projectUrl };
function response() {
  return { headers: {}, statusCode: 0, body: undefined,
    setHeader(name, value) { this.headers[name] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; }, end() { return this; } };
}

test('Auth proxy allows only email login, refresh, own user and local sign-out paths', async () => {
  let calls = 0;
  const handler = createAuthHandler({ env, fetchImpl: async () => { calls++; throw new Error(); } });
  for (const url of ['/api/auth?authPath=admin/users', '/api/auth?authPath=../rest/v1/notes',
    '/api/auth?authPath=token&grant_type=client_credentials', '/api/auth?authPath=logout&scope=global',
    '/api/auth?authPath=token&authPath=user&grant_type=password',
    '/api/auth?authPath=user&url=https://example.invalid']) {
    const res = response();
    await handler({ url, method: 'POST', headers: {}, body: {} }, res);
    assert.equal(res.statusCode, 400);
  }
  for (const [method, url] of [['GET', '/api/auth?authPath=user'],
    ['POST', '/api/auth?authPath=logout&scope=local']]) {
    const res = response();
    await handler({ url, method, headers: {} }, res);
    assert.equal(res.statusCode, 401);
  }
  assert.equal(calls, 0);
});

test('missing config, invalid login input and upstream failures never disclose request data', async () => {
  const req = { url: '/api/auth?authPath=token&grant_type=password', method: 'POST', headers: {}, body: {} };
  for (const [options, status] of [[{ env: {} }, 503], [{ env }, 400]]) {
    const res = response();
    await createAuthHandler({ ...options, fetchImpl: async () => { throw new Error(); } })(req, res);
    assert.equal(res.statusCode, status);
  }
  const res = response();
  await createAuthHandler({ env, fetchImpl: async () => { throw new Error('fixture-only'); } })({ ...req,
    body: { email: ['fixture', 'example.invalid'].join('@'), password: 'fixture-only' } }, res);
  assert.equal(res.statusCode, 502);
  assert.equal(JSON.stringify(res.body).includes('fixture-only'), false);
  assert.equal(res.headers['Cache-Control'], 'no-store');
});

test('official SDK login, refresh and local sign-out use the proxy without a browser API key', async () => {
  const source = await readFile(new URL('../public/auth.js', import.meta.url), 'utf8');
  assert.equal(/sb_publishable_[A-Za-z0-9_-]{8,}/u.test(source), false);
  const prefix = source.slice(source.indexOf('  const projectUrl'), source.indexOf('  const form'));
  const { privateKey } = await generateKeyPair('ES256');
  const user = { id: randomUUID(), aud: 'authenticated', role: 'authenticated' };
  const accessToken = await new SignJWT({ sub: user.id, role: user.role, aud: user.aud,
    iss: config.identityProvider.issuer }).setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt().setExpirationTime('5m').sign(privateKey);
  const session = { access_token: accessToken, refresh_token: randomUUID(),
    token_type: 'bearer', expires_in: 300, user };
  const operations = [];
  const handler = createAuthHandler({ env, fetchImpl: async (input, init) => {
    const url = new URL(input);
    assert.equal(url.origin, projectUrl);
    assert.ok(init.headers.apikey);
    assert.notEqual(init.headers.apikey, 'server-auth');
    operations.push(url.pathname === '/auth/v1/token' ? url.searchParams.get('grant_type') : 'logout');
    if (url.pathname === '/auth/v1/logout') {
      assert.equal(init.headers.Authorization, `Bearer ${accessToken}`);
      return new Response(null, { status: 204 });
    }
    assert.equal(init.headers.Authorization, undefined);
    return Response.json(session);
  } });
  const authFetch = runInNewContext(`${prefix}\nauthFetch`, { URL, URLSearchParams, Headers, Request,
    fetch: async (path, init) => {
      assert.ok(path.startsWith('/api/auth?'));
      assert.equal(init.headers.has('apikey'), false);
      assert.notEqual(init.headers.get('Authorization'), 'Bearer server-auth');
      const res = response();
      await handler({ url: path, method: init.method ?? 'GET',
        headers: Object.fromEntries([...init.headers].map(([k, v]) => [k.toLowerCase(), v])),
        body: init.body }, res);
      return res.statusCode === 204 ? new Response(null, { status: 204 })
        : Response.json(res.body, { status: res.statusCode, headers: res.headers });
    } });
  const client = createClient(projectUrl, 'server-auth', {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: authFetch },
  });
  const signIn = await client.auth.signInWithPassword({ email: ['fixture', 'example.invalid'].join('@'),
    password: 'fixture-only' });
  assert.equal(signIn.error, null);
  assert.equal(signIn.data.session.user.id, user.id);
  assert.equal((await client.auth.refreshSession()).error, null);
  assert.equal((await client.auth.signOut({ scope: 'local' })).error, null);
  assert.equal((await client.auth.getSession()).data.session, null);
  assert.deepEqual(operations, ['password', 'refresh_token', 'logout']);
  assert.throws(() => authFetch(`${projectUrl}/rest/v1/notes`, {}));
});

test('Auth API response version preserves official SDK login error codes', async () => {
  const handler = createAuthHandler({ env, fetchImpl: async () => Response.json({
    code: 'invalid_credentials', message: 'Invalid login credentials',
  }, { status: 400, headers: { 'X-Supabase-Api-Version': '2024-01-01' } }) });
  const client = createClient(projectUrl, 'server-auth', {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { fetch: async (_url, init) => {
      const res = response();
      await handler({ url: '/api/auth?authPath=token&grant_type=password', method: 'POST',
        headers: {}, body: init.body }, res);
      return Response.json(res.body, { status: res.statusCode, headers: res.headers });
    } },
  });
  const result = await client.auth.signInWithPassword({
    email: ['fixture', 'example.invalid'].join('@'), password: 'fixture-only',
  });
  assert.equal(result.error?.code, 'invalid_credentials');
  assert.equal(result.data.session, null);
});
