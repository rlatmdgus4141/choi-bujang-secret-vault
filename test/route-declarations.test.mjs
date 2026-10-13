import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'fixture',
  VERCEL_GIT_REPO_SLUG: 'vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'fixture.vercel.app' };

test('serialized deployment metadata declares GET /api/notes literally and every declared endpoint exists', async () => {
  const published = JSON.parse(JSON.stringify(deploymentIdentity(env, config)));
  assert.ok(published.allowedRoutes.includes('GET /api/notes'));
  assert.ok(published.allowedRoutes.every(route => typeof route === 'string'));
  for (const route of published.allowedRoutes) {
    const path = route.split(' ')[1];
    await access(new URL(`..${path.replace('/:id', '/[id]')}.js`, import.meta.url));
  }
  const previous = published.allowedRoutes[0];
  published.allowedRoutes[0] = 'GET /other';
  assert.equal(config.allowedRoutes[0], previous);
});

test('deployment build rejects ambiguous legacy objects, duplicates and malformed route selectors', () => {
  for (const allowedRoutes of [[], [{ method: 'GET', path: '/api/notes' }],
    ['GET /api/notes', 'GET /api/notes'], ['GET'], ['GET /api/notes?owner_id=other'],
    ['GET /api/notes#fragment'], ['get /api/notes'], ['GET /api/../notes'], ['GET  /api/notes']]) {
    assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes }), /허용 경로/u);
  }
});
