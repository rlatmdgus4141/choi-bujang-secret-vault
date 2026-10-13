import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT, jwtVerify } from 'jose';
import { previewPolicy, restoreTestPolicy } from '../src/recovery-policy.mjs';
import { createRestoreHandler } from '../api/restore.js';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import { checkRecovery } from '../scripts/check-recovery.mjs';

async function trial(run) {
  const root = await mkdtemp(join(tmpdir(), 'vault-recovery-'));
  await mkdir(join(root, 'recovery'));
  const baseline = await readFile(new URL('../recovery/policy-baseline.json', import.meta.url), 'utf8');
  await writeFile(join(root, 'recovery/policy-baseline.json'), baseline);
  const source = JSON.parse(baseline).source;
  await writeFile(join(root, 'recovery/test-decider.mjs'), source);
  const other = join(root, 'another-service-policy.json');
  await writeFile(other, '{"unchanged":true}');
  const audit = join(root, 'recovery/policy-audit.log');
  await writeFile(audit, 'existing-audit\n');
  try { await run({ root, source, other, audit }); } finally { await rm(root, { recursive: true }); }
}
test('test policy restore previews actual changes and preserves unrelated policy and audit', async () => {
  await trial(async ({ root, source, other, audit }) => {
    const path = join(root, 'recovery/test-decider.mjs');
    await writeFile(path, source.replace("return reply('deny', 'device_not_registered'", "return reply('allow', 'device_not_registered'"));
    const plan = await previewPolicy(root);
    assert.equal(plan.changes.length, 1);
    assert.equal(plan.productionChanged, false);
    await assert.rejects(restoreTestPolicy(root, 'unreviewed'));
    await restoreTestPolicy(root, plan.confirmation);
    assert.equal(await readFile(path, 'utf8'), source);
    assert.equal(await readFile(other, 'utf8'), '{"unchanged":true}');
    assert.ok((await readFile(audit, 'utf8')).startsWith('existing-audit\n'));
    const { decide } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
    assert.equal((await decide(fixtureRequests().normal)).decision, 'allow');
    assert.equal((await decide({ ...fixtureRequests().normal, deviceRegistered: false })).decision, 'deny');
    assert.equal((await decide({ ...fixtureRequests().normal, path: '/notes', route: 'GET /notes' })).decision, 'deny');
  });
});
test('missing or corrupt safe copy and stale preview stop without modifying trial policy or audit', async () => {
  await trial(async ({ root, source, audit }) => {
    const target = join(root, 'recovery/test-decider.mjs');
    const plan = await previewPolicy(root);
    await writeFile(target, source + '\n// another change\n');
    await assert.rejects(restoreTestPolicy(root, plan.confirmation));
    const unchanged = await readFile(target, 'utf8');
    const path = join(root, 'recovery/policy-baseline.json');
    const validBackup = JSON.parse(await readFile(path, 'utf8'));
    for (const patch of [{ version: 'unverified version' }, { commit: 'a'.repeat(40) }]) {
      await writeFile(path, JSON.stringify({ ...validBackup, ...patch }));
      await assert.rejects(previewPolicy(root), /검증 실패/u);
    }
    const corrupt = structuredClone(validBackup); corrupt.source += '\n';
    await writeFile(path, JSON.stringify(corrupt));
    await assert.rejects(previewPolicy(root), /검증 실패/u);
    await rm(path);
    await assert.rejects(previewPolicy(root));
    assert.equal(await readFile(target, 'utf8'), unchanged);
    assert.equal(await readFile(audit, 'utf8'), 'existing-audit\n');
  });
});
test('recovery check re-reads a verified copy, restores it, then executes normal and forbidden API/policy requests', async () => {
  const report = await checkRecovery();
  assert.equal(report.backupVerified, true);
  assert.equal(report.retestPassed, true);
  assert.equal(report.checks.length, 6);
  assert.equal(report.retests.length, 39);
  assert.ok(report.checks.every(x => x.passed) && report.retests.every(x => x.passed));
  assert.equal(report.productionPolicyChanged, false);
  assert.equal(report.scope, 'local_synthetic_only');
  assert.ok(report.unexecuted.includes('live_browser_B_restore'));
  assert.ok(report.retests.some(x => x.name === 'A_other_GET' && x.actual === 404));
  assert.ok(report.retests.some(x => x.name === 'B_own_read' && x.actual === 200));
  assert.ok(report.retests.some(x => x.name === 'token_expired' && x.actual === 401));
  assert.equal(JSON.stringify(report).includes('Bearer'), false);
});

const pair = await generateKeyPair('ES256');
const owner = randomUUID(), noteId = randomUUID();
const env = { SUPABASE_URL: new URL(config.identityProvider.issuer).origin,
  SUPABASE_SECRET_KEY: ['sb','secret','fixture'].join('_') };
const authorization = async (sub = owner, patch = {}) => `Bearer ${await new SignJWT({
  iss: config.identityProvider.issuer, aud: 'authenticated', role: 'authenticated', sub,
  exp: Math.floor(Date.now()/1000)+300, ...patch,
}).setProtectedHeader({ alg: 'ES256' }).sign(pair.privateKey)}`;
const response = () => ({ statusCode: 0, headers: {}, setHeader(k,v) { this.headers[k]=v; },
  status(code) { this.statusCode=code; return this; }, json(body) { this.body=body; return this; } });
function fixture({ error, foreign = false, hash = 'a'.repeat(64) } = {}) {
  const calls = [];
  const handler = createRestoreHandler({ env, clientFactory: () => ({
    auth: { async getClaims(token) {
      try { return { data: { claims: (await jwtVerify(token, pair.publicKey)).payload }, error: null }; }
      catch { return { data: null, error: {} }; }
    } },
    async rpc(name, args) {
      calls.push({ name, args });
      if (error || args.p_owner !== owner) return { data: null, error: error ?? { code: 'P0002' } };
      return { data: { id: args.p_id, owner_id: foreign ? randomUUID() : owner,
        hash, restored: !args.p_dry_run, backupVersion: 'stage10-v1', content: 'must not escape' }, error: null };
    },
  }) });
  return { handler, calls };
}
const request = (authorization, body = { id: noteId }, patch = {}) => ({ method: 'POST',
  url: '/api/restore', headers: { authorization }, query: {}, body, ...patch });
test('restore authenticates before DB access, never trusts owner or role and rejects expired tokens', async () => {
  const { handler, calls } = fixture();
  for (const auth of [undefined, 'Bearer invalid', await authorization(owner, { exp: 1 })]) {
    const res = response(); await handler(request(auth), res); assert.equal(res.statusCode, 401);
  }
  const auth = await authorization();
  for (const input of [{ id: noteId, owner_id: owner }, { id: noteId, role: 'admin' },
    { id: '../notes' }, { id: noteId, dryRun: 'true' }]) {
    const res = response(); await handler(request(auth, input), res); assert.equal(res.statusCode, 400);
  }
  assert.equal(calls.length, 0);
});
test('restore and dry run bind verified owner and return only verified ID/hash/version metadata', async () => {
  const { handler, calls } = fixture();
  for (const dryRun of [true, false]) {
    const res = response(); await handler(request(await authorization(), { id: noteId, dryRun }), res);
    assert.equal(res.statusCode, 200); assert.equal(res.body.restored, !dryRun);
    assert.deepEqual(Object.keys(res.body).sort(), ['backupVersion','hash','id','restored']);
  }
  assert.ok(calls.every(c => c.name === 'vault_restore_note' && c.args.p_owner === owner));
});
test('foreign owner, broken backup, DB failure and mismatched response never return note content', async () => {
  const cases = [
    { options: {}, subject: randomUUID(), status: 404 },
    { options: { error: { code: '22000' } }, status: 409 },
    { options: { error: { code: 'XX000', message: env.SUPABASE_SECRET_KEY } }, status: 502 },
    { options: { foreign: true }, status: 502 }, { options: { hash: 'bad' }, status: 502 },
  ];
  for (const c of cases) {
    const res = response(); await fixture(c.options).handler(request(await authorization(c.subject)), res);
    assert.equal(res.statusCode, c.status); assert.deepEqual(Object.keys(res.body), ['error']);
    assert.ok(!JSON.stringify(res.body).includes(env.SUPABASE_SECRET_KEY));
  }
});
test('restore permits only its exact POST route without query selectors', async () => {
  const { handler, calls } = fixture(); const auth = await authorization();
  for (const patch of [{ method: 'GET' }, { url: '/api/restore?mode=all' }, { query: { id: noteId } }]) {
    const res = response(); await handler(request(auth, undefined, patch), res);
    assert.ok([400,405].includes(res.statusCode));
  }
  assert.equal(calls.length, 0);
});
