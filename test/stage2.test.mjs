import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

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
      return Response.json(new URL(url).pathname === '/data.json' ? { notes: [] }
        : { sampleMarker: 'SAMPLE_NOTE_1', notes: Array.from({ length: 4 },
          () => ({ title: 'fixture', content: 'test-only' })) });
    };
    const attempts = await runAttackChecks({ step: 2, sampleMarker: 'SAMPLE_NOTE_1',
      publicAppUrl: 'https://fixture.vercel.app' });
    assert.deepEqual(calls.map(call => call.path), ['/data.json', '/api/notes']);
    assert.ok(calls.every(call => !call.options.headers && call.options.redirect === 'error'));
    assert.match(attempts[0].observed, /메모 0건/u);
    assert.match(attempts[0].observed, /확인 표시 없음/u);
    assert.match(attempts[1].observed, /인증은 다음 단계/u);
    assert.equal(JSON.stringify(attempts).includes('test-only'), false);
  } finally { globalThis.fetch = original; }
});

test('an empty static memo list still fails if the stage 1 marker remains', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async url => Response.json({ sampleMarker: 'SAMPLE_NOTE_1',
      notes: new URL(url).pathname === '/data.json' ? []
        : Array.from({ length: 4 }, () => ({ title: 'fixture', content: 'test-only' })),
    });
    const [result] = await runAttackChecks({ step: 2, sampleMarker: 'SAMPLE_NOTE_1',
      publicAppUrl: 'https://fixture.vercel.app' });
    assert.match(result.observed, /확인 실패/u);
  } finally { globalThis.fetch = original; }
});
