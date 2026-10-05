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
  // Vercel records the immutable deployment URL, not the production alias.
  publicAppUrl: 'https://fixture-deployment.vercel.app',
});

function passingResponse(url) {
  const path = new URL(url).pathname;
  if (path === '/data.json') return Response.json({ notes: [] });
  if (path === '/rest/v1/notes') return Response.json({ code: '42501' }, { status: 401 });
  return Response.json({ error: 'login required' }, { status: 401 });
}

test('strict self-checks preserve the submission schema when all actual responses pass', async () => {
  const previous = globalThis.fetch;
  try {
    globalThis.fetch = async url => passingResponse(url);
    const attempts = await runAttackChecks(config, { requirePass: true });
    assert.equal(attempts.length, 9);
    assert.ok(attempts.every(attempt =>
      Object.keys(attempt).sort().join(',') === 'attackId,expected,observed'));
    assert.equal(JSON.stringify(attempts).includes('sb_publishable_'), false);
  } finally { globalThis.fetch = previous; }
});

test('strict self-checks reject leaked static data, permitted app access and direct API regressions', async () => {
  const previous = globalThis.fetch;
  const regressions = [
    { id: 'static_note_seed_read', match: (url) => url.pathname === '/data.json',
      response: () => Response.json({ notes: [{}] }) },
    { id: 'anonymous_note_read', match: (url, init) => url.pathname === '/api/notes'
        && init.method === 'GET' && !init.headers,
      response: () => Response.json([]) },
    { id: 'anon_original_read', match: (url, init) => url.pathname === '/rest/v1/notes'
        && init.method === 'GET',
      response: () => Response.json([]) },
    { id: 'anon_original_update', match: (url, init) => url.pathname === '/rest/v1/notes'
        && init.method === 'PATCH',
      response: () => new Response(null, { status: 204 }) },
    { id: 'anon_original_read', match: (url, init) => url.pathname === '/rest/v1/notes'
        && init.method === 'GET',
      // An invalid key is not evidence that table grants deny access.
      response: () => Response.json({ message: 'Invalid API key' }, { status: 401 }) },
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
    ['step', value => { value.step = 4; }],
    ['repoUrl', value => { value.repoUrl = 'https://github.com/fixture/other'; }],
    ['commit', value => { value.commit = 'b'.repeat(40); }],
    ['judgeIssuer', value => { value.judgeIssuer += '/other'; }],
    ['identityProvider', value => { value.identityProvider.audience = 'another-service'; }],
    ['allowedRoutes', value => { value.allowedRoutes.pop(); }],
    ['allowedRoutes', value => { value.allowedRoutes[0].method = 'POST'; }],
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
