import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

function response() {
  return { headers: {}, statusCode: 0, body: undefined,
    setHeader(name, value) { this.headers[name] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
}
const key = ['sb', 'secret', 'test'].join('_');
const env = { SUPABASE_URL: 'https://fixture.supabase.co', SUPABASE_SECRET_KEY: key };

test('API reads on the server, restricts returned fields, and disables caching', async () => {
  let factoryCalls = 0;
  const handler = createNotesHandler({ env, clientFactory(url, secret, options) {
    factoryCalls++;
    assert.equal(url, env.SUPABASE_URL);
    assert.equal(secret, key);
    assert.equal(options.auth.persistSession, false);
    return { from(table) {
      assert.equal(table, 'notes');
      return { select(fields) {
        assert.equal(fields, 'id,title,content');
        return { async order(column) {
          assert.equal(column, 'position');
          return { error: null, data: Array.from({ length: 4 }, (_, i) => ({
            id: String(i), title: 'fixture', content: 'test-only', extra: key,
          })) };
        } };
      } };
    } };
  } });
  const res = response();
  await handler({ method: 'GET' }, res);
  assert.equal(factoryCalls, 1);
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  assert.equal(res.body.notes.length, 4);
  assert.equal(JSON.stringify(res.body).includes(key), false);
  assert.deepEqual(Object.keys(res.body.notes[0]).sort(), ['content', 'id', 'title']);
});

test('missing credentials, client keys, database errors and mutations fail without leaking details', async () => {
  for (const invalid of [{}, { ...env, SUPABASE_SECRET_KEY: 'client-key' }]) {
    const res = response();
    await createNotesHandler({ env: invalid })({ method: 'GET' }, res);
    assert.equal(res.statusCode, 503);
  }
  const res = response();
  await createNotesHandler({ env, clientFactory() { throw new Error(key); } })({ method: 'GET' }, res);
  assert.equal(res.statusCode, 502);
  assert.equal(JSON.stringify(res.body).includes(key), false);
  const post = response();
  await createNotesHandler({ env })({ method: 'POST' }, post);
  assert.equal(post.statusCode, 405);
  assert.equal(post.headers.Allow, 'GET');
});

test('deployment identity records stage 2 from verified Vercel metadata', () => {
  const identity = deploymentIdentity({ VERCEL_GIT_PROVIDER: 'github',
    VERCEL_GIT_REPO_OWNER: 'fixture', VERCEL_GIT_REPO_SLUG: 'vault',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'fixture.vercel.app',
  }, { step: 2, sampleMarker: 'SAMPLE_NOTE_1',
    judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge' });
  assert.equal(identity.step, 2);
  assert.equal(identity.commit, 'a'.repeat(40));
});

test('bundle checks distinguish empty static data from the remaining public API weakness', async () => {
  const original = globalThis.fetch;
  const calls = [];
  try {
    globalThis.fetch = async (url, options) => {
      calls.push({ path: new URL(url).pathname, options });
      return Response.json({ sampleMarker: 'SAMPLE_NOTE_1', notes: new URL(url).pathname === '/data.json'
        ? [] : Array.from({ length: 4 }, () => ({ title: 'fixture', content: 'test-only' })) });
    };
    const attempts = await runAttackChecks({ step: 2, sampleMarker: 'SAMPLE_NOTE_1',
      publicAppUrl: 'https://fixture.vercel.app' });
    assert.deepEqual(calls.map(call => call.path), ['/data.json', '/api/notes']);
    assert.ok(calls.every(call => !call.options.headers && call.options.redirect === 'error'));
    assert.match(attempts[0].observed, /메모 0건/u);
    assert.match(attempts[1].observed, /인증은 다음 단계/u);
    assert.equal(JSON.stringify(attempts).includes('test-only'), false);
  } finally { globalThis.fetch = original; }
});
