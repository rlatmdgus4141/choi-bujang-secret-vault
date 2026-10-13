import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT, jwtVerify } from 'jose';
import { createNotesHandler } from '../api/notes.js';
import { decide } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };

// Signed identities are verified in memory. No real key, password or JWT is stored.
const pair = await generateKeyPair('ES256');
const a = randomUUID(), b = randomUUID(), id = randomUUID();
const env = { SUPABASE_URL: new URL(config.identityProvider.issuer).origin,
  SUPABASE_SECRET_KEY: ['sb', 'secret', 'fixture'].join('_') };
const authorization = async subject => `Bearer ${await new SignJWT({
  iss: config.identityProvider.issuer, aud: 'authenticated', role: 'authenticated',
  sub: subject, exp: Math.floor(Date.now() / 1000) + 300,
}).setProtectedHeader({ alg: 'ES256' }).sign(pair.privateKey)}`;
const row = owner => ({ id, title: 'restricted fixture', content: 'test-only', owner_id: owner });

async function read(subject, returned, itemRoute) {
  if (itemRoute) {
    // The verified engine pseudonym is not a raw Supabase user UUID. API ownership remains separate.
    const gate = await decide({ ...fixtureRequests().normal,
      subjectId: subject === a ? 'fixture_engine_subject_A' : 'fixture_engine_subject_B',
      path: `/api/notes/${id}`, route: 'GET /api/notes/:id' });
    assert.equal(gate.decision, 'allow');
  }
  const calls = [];
  const clientFactory = () => ({
    auth: { async getClaims(value) {
      return { data: { claims: (await jwtVerify(value, pair.publicKey)).payload } };
    } },
    from(table) {
      assert.equal(table, 'notes');
      return {
        select(fields) { assert.equal(fields, 'id,title,content,owner_id'); return this; },
        eq(key, value) { calls.push([key, value]); return this; },
        async maybeSingle() { return { data: returned, error: null }; },
        async order() { return { data: returned, error: null }; },
      };
    },
  });
  const res = { headers: {}, statusCode: 0,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await createNotesHandler({ clientFactory, env, itemRoute })({
    method: 'GET', url: itemRoute ? `/api/notes/${id}` : '/api/notes',
    query: itemRoute ? { id } : {}, headers: { authorization: await authorization(subject) },
  }, res);
  assert.deepEqual(calls, itemRoute ? [['id', id], ['owner_id', subject]] : [['owner_id', subject]]);
  assert.equal(res.headers['Cache-Control'], 'no-store');
  return res;
}

test('stored-owner read: either verified account can read its own row, with ownership omitted from response', async () => {
  for (const subject of [a, b]) for (const item of [true, false]) {
    const res = await read(subject, item ? row(subject) : [row(subject)], item);
    assert.equal(res.statusCode, 200);
    assert.deepEqual(item ? res.body : res.body[0], { id, title: 'restricted fixture', body: 'test-only' });
    assert.equal(JSON.stringify(res.body).includes('owner_id'), false);
  }
});

test('stored-owner read: foreign, absent, malformed ownership and wrong resource ID never return a body', async () => {
  for (const returned of [row(b), row(null), row(undefined), row([a]), { ...row(a), id: randomUUID() }]) {
    const res = await read(a, returned, true);
    assert.equal(res.statusCode, 404);
    assert.deepEqual(Object.keys(res.body), ['error']);
    assert.equal(JSON.stringify(res.body).includes('test-only'), false);
  }
});

test('stored-owner list: a mixed-owner or ownerless upstream response is rejected as a whole', async () => {
  for (const returned of [[row(a), row(b)], [row(a), row(null)], [row(a), row(undefined)]]) {
    const res = await read(a, returned, false);
    assert.equal(res.statusCode, 502);
    assert.deepEqual(Object.keys(res.body), ['error']);
    assert.equal(JSON.stringify(res.body).includes('test-only'), false);
  }
  const empty = await read(a, [], false);
  assert.equal(empty.statusCode, 200);
  assert.deepEqual(empty.body, []);
});
