import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runAttackChecks } from '../src/attack-check.mjs';
import { assertDeploymentMetadata, verifyDeployment } from '../scripts/verify-deployment.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const commit = 'a'.repeat(40);
const identity = () => ({
  schema: 'aleph.defense.deployment.v1', step: config.step,
  repoUrl: config.repoUrl, commit, judgeIssuer: config.judgeIssuer,
  sampleMarker: config.sampleMarker,
  identityProvider: structuredClone(config.identityProvider),
  allowedRoutes: structuredClone(config.allowedRoutes),
  originalApiUrl: config.originalApiUrl,
  restoreRoute: config.restoreRoute,
  // Vercel records the immutable deployment URL, not the production alias.
  publicAppUrl: 'https://fixture-deployment.vercel.app',
});

function passingResponse(url) {
  const path = new URL(url).pathname;
  if(path==='/api/operations')return Response.json({step:12,commit,engine:{name:'ALEPH SDP 엔진'},
    officialAttacks:{verified:0,status:'unexecuted'}},{headers:{'x-vault-request-id':'11111111-1111-4111-8111-111111111111','x-vault-checked-at':new Date().toISOString()}});
  if(path==='/operations-verification.json')return Response.json({commit,passed:true});
  if (path === '/manifest.webmanifest') return Response.json({start_url:'/',scope:'/',display:'standalone',icons:[{src:'/icons/icon-192.png'},{src:'/icons/icon-512.png'}]});
  if (path.startsWith('/icons/')) return new Response(new Uint8Array([137,80,78,71]), {headers:{'content-type':'image/png'}});
  if (path === '/sw.js') return new Response("url.pathname.startsWith('/api/') /offline.html");
  if (path === '/offline.html') return new Response('offline guide');
  if (path === '/data.json') return Response.json({ notes: [] });
  if (path === '/rest/v1/notes') return Response.json({ code: '42501' }, { status: 401 });
  if (path === '/') return new Response('<script src="/auth.js"></script>', {
    headers: { 'X-Content-Type-Options': 'nosniff' } });
  if (path === '/auth.js') return new Response('server-auth');
  return Response.json({ error: 'login required' }, { status: 401 });
}

test('strict self-checks preserve the submission schema when all actual responses pass', async () => {
  const previous = globalThis.fetch;
  const originalRead = fs.readFileSync;
  fs.readFileSync = (path, ...args) => {
    if (typeof path !== 'string') throw new Error('path_format');
    return originalRead(path, ...args);
  };
  syncBuiltinESMExports();
  try {
    globalThis.fetch = async (url, init = {}) => {
      assert.ok(['GET', 'HEAD'].includes(init.method ?? 'GET'));
      assert.equal(new URL(url).protocol, 'https:');
      assert.equal(init.redirect, 'error');
      const response = passingResponse(url);
      // The judge exposes get(), but not the complete browser Headers API.
      return { status: response.status, ok: response.ok,
        headers: { get: name => response.headers.get(name) },
        json: () => response.json(), text: () => response.text() };
    };
    const attempts = await runAttackChecks(config, { requirePass: true });
    assert.equal(attempts.length, 20);
    assert.equal(attempts.filter(item => item.observed === 'not_run').length, 11);
    const local = attempts.filter(attempt => attempt.attackId.startsWith('local_'));
    assert.equal(local.length, config.step >= 11 ? 1 : 3);
    assert.ok(attempts.some(x => x.attackId === 'single_note_restore_matches'));
    assert.ok(attempts.some(x => x.attackId === 'restore_preserves_other_records'));
    assert.ok(attempts.some(x => x.attackId === 'backup_verified'));
    assert.ok(attempts.some(x => x.attackId === 'post_restore_retest'));
    assert.ok(local.every(attempt => attempt.observed === 'not_run'));
    assert.ok(attempts.every(attempt =>
      Object.keys(attempt).sort().join(',') === 'attackId,expected,observed'));
    assert.equal(JSON.stringify(attempts).includes('sb_publishable_'), false);
  } finally {
    globalThis.fetch = previous;
    fs.readFileSync = originalRead;
    syncBuiltinESMExports();
  }
});

test('strict self-checks reject leaked static data, permitted app access and direct API regressions', async () => {
  const previous = globalThis.fetch;
  const regressions = [
    { id: 'operations_evidence_and_installable_app', match: url => url.pathname.startsWith('/icons/'),
      response: () => new Response('not an image', {headers:{'content-type':'text/html'}}) },
    ...['x-vault-request-id', 'x-vault-checked-at'].map(header => ({
      id: 'operations_evidence_and_installable_app',
      match: url => url.pathname === '/api/operations',
      response: () => {
        const response = passingResponse(`${config.publicAppUrl}/api/operations`);
        response.headers.delete(header);
        return response;
      },
    })),
    { id: 'static_note_seed_read', match: (url) => url.pathname === '/data.json',
      response: () => Response.json({ notes: [{}] }) },
    { id: 'anonymous_note_read', match: (url, init) => url.pathname === '/api/notes'
        && init.method === 'GET' && !init.headers,
      response: () => Response.json([]) },
    { id: 'anon_original_read', match: (url, init) => url.pathname === '/rest/v1/notes'
        && init.method === 'GET',
      response: () => Response.json([]) },
    { id: 'anon_original_read', match: (url, init) => url.pathname === '/rest/v1/notes'
        && init.method === 'GET',
      // An invalid key is not evidence that table grants deny access.
      response: () => Response.json({ message: 'Invalid API key' }, { status: 401 }) },
    { id: 'home_security_header', match: url => url.pathname === '/',
      response: () => new Response('<script src="/auth.js"></script>') },
    { id: 'browser_public_key_absent', match: url => url.pathname === '/auth.js',
      response: () => new Response(['sb', 'publishable', 'fixture-public-key'].join('_')) },
  ];
  try {
    for (const regression of regressions) {
      globalThis.fetch = async (url, init) => regression.match(new URL(url), init)
        ? regression.response() : passingResponse(url);
      const report = await runAttackChecks(config);
      assert.match(report.find(item => item.attackId === regression.id).observed, /확인 실패/u);
      await assert.rejects(runAttackChecks(config, { requirePass: true }), error =>
        error.message.includes(regression.id) && !error.message.includes('Invalid API key'));
    }
  } finally { globalThis.fetch = previous; }
});

test('deployment verification rejects stale identity and mismatched auth, routes or original API', () => {
  assert.doesNotThrow(() => assertDeploymentMetadata(identity(), config, commit));
  const mismatches = [
    ['restoreRoute', value => { value.restoreRoute = '/api/other'; }],
    ['step', value => { value.step = 4; }],
    ['repoUrl', value => { value.repoUrl = 'https://github.com/fixture/other'; }],
    ['commit', value => { value.commit = 'b'.repeat(40); }],
    ['judgeIssuer', value => { value.judgeIssuer += '/other'; }],
    ['identityProvider', value => { value.identityProvider.audience = 'another-service'; }],
    ['allowedRoutes', value => { value.allowedRoutes.pop(); }],
    ['allowedRoutes', value => { value.allowedRoutes[0] = 'POST /api/notes'; }],
    ['originalApiUrl', value => { value.originalApiUrl += '?select=*'; }],
    ['originalApiUrl', value => { delete value.originalApiUrl; }],
  ];
  for (const [field, change] of mismatches) {
    const candidate = identity();
    change(candidate);
    assert.throws(() => assertDeploymentMetadata(candidate, config, commit), error =>
      error.message.includes(field) && !error.message.includes('https://'));
  }
  assert.throws(() => assertDeploymentMetadata(null, config, commit));
});

test('deployment preflight requests uncached identity and stops on HTTP or JSON failures', async () => {
  const calls = [];
  await verifyDeployment(config, commit, { fetchImpl: async (url, options) => {
    calls.push({ url: String(url), options });
    return Response.json(identity());
  } });
  assert.equal(calls[0].url, `${config.publicAppUrl}/aleph.json`);
  assert.equal(calls[0].options.redirect, 'error');
  assert.equal(calls[0].options.cache, 'no-store');
  assert.equal(calls[0].options.headers, undefined);
  for (const response of [
    () => new Response('unavailable', { status: 503 }),
    () => new Response('<html>not deployment metadata</html>'),
    () => Response.json({ ...identity(), commit: 'b'.repeat(40) }),
  ]) {
    await assert.rejects(verifyDeployment(config, commit, { fetchImpl: async () => response() }));
  }
});
