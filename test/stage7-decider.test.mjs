import test from 'node:test';
import assert from 'node:assert/strict';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
const { normal, suspicious } = fixtureRequests();
const expect = async (request, decision, reason) => {
  const out = await decide(request);
  assert.equal(out.decision, decision);
  if (reason) assert.equal(out.reasonCode, reason);
  assert.equal(Object.keys(out).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
  assert.equal(out.requestId, request.requestId);
  assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)));
  return out;
};
test('stage 7 normal reads allow; compound risks require step-up without returning data', async () => {
  await expect(normal, 'allow', 'approved');
  for (const signals of [
    { ...normal.signals, region: 'foreign', hour: 3 },
    { ...normal.signals, network: 'unusual', hour: 3 },
    { ...normal.signals, network: 'unusual' },
  ]) {
    await expect({ ...normal, signals, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] },
      'step_up', 'step_up_required');
  }
  await expect(suspicious, 'step_up', 'step_up_required');
});
test('stage 7 no single region, time, network or activity signal creates permanent denial', async () => {
  for (const change of [{ signals: { ...normal.signals, region: 'foreign' } },
    { signals: { ...normal.signals, hour: 3 } }, { signals: { ...normal.signals, network: 'unusual' } },
    { recentEvents: [{ kind: 'risk_signal', ageSeconds: 0, count: 100 }] }]) {
    await expect({ ...normal, ...change }, 'allow');
  }
});
test('stage 7 only exact verified status with valid fresh engine age clears compound risk', async () => {
  for (const age of [0, 60, 900]) await expect({ ...suspicious, stepUp: { verified: true, authAgeSeconds: age } }, 'allow');
  for (const stepUp of [undefined, null, {}, { verified: false, authAgeSeconds: 0 },
    { verified: 'true', authAgeSeconds: 0 }, { verified: true, authAgeSeconds: null },
    { verified: true, authAgeSeconds: '60' }, { verified: true, authAgeSeconds: -1 },
    { verified: true, authAgeSeconds: 901 }, { verified: true, authAgeSeconds: NaN }]) {
    await expect({ ...suspicious, stepUp }, 'step_up', 'step_up_required');
  }
  await expect({ ...suspicious, deviceRegistered: false, stepUp: { verified: true, authAgeSeconds: 0 } },
    'deny', 'device_not_registered');
});
test('stage 7 unknown source and malformed or missing signals are never filled with normal defaults', async () => {
  for (const signals of [undefined, null, {}, { ...normal.signals, source: 'client' },
    { ...normal.signals, source: 'forwarded-header' }, { ...normal.signals, hour: '3' },
    { ...normal.signals, hour: 24 }, { ...normal.signals, network: undefined },
    { ...normal.signals, region: undefined }, { ...normal.signals, source: 'none' }]) {
    await expect({ ...normal, signals }, 'deny', 'starter_not_ready');
  }
  for (const recentEvents of [undefined, null, Array(13).fill({ kind: 'risk_signal', count: 1, ageSeconds: 1 }),
    [{ kind: 'risk_signal', count: '20', ageSeconds: 1 }], [{ kind: 'risk_signal', count: 20, ageSeconds: -1 }]]) {
    await expect({ ...normal, recentEvents }, 'deny');
  }
});
test('stage 7 headers cannot change trusted engine signals or step-up status; none stays unknown', async () => {
  const headers = { 'x-region': 'local', 'x-network': 'usual', 'x-step-up': 'true', 'x-auth-age': '0' };
  await expect({ ...suspicious, headers }, 'step_up');
  const live = { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null } };
  const snapshot = JSON.stringify(live);
  await expect({ ...live, headers: { 'x-region': 'foreign' } }, 'allow');
  assert.equal(JSON.stringify(live), snapshot);
});
test('stage 7 recent activity uses the supplied event kind and window; fresh login never expands routes', async () => {
  const request = { ...normal, signals: { ...normal.signals, network: 'unusual' } };
  for (const event of [{ kind: 'risk_signal', ageSeconds: 301, count: 20 },
    { kind: 'unknown_event', ageSeconds: 60, count: 20 }, { kind: 'risk_signal', ageSeconds: 60, count: 9 }]) {
    await expect({ ...request, recentEvents: [event] }, 'allow');
  }
  await expect({ ...request, recentEvents: [{ kind: 'risk_signal', ageSeconds: 300, count: 10 }] }, 'step_up');
  await expect({ ...suspicious, method: 'PUT' }, 'deny');
  await expect({ ...suspicious, method: 'PUT', path: '/notes/11111111-1111-4111-8111-111111111111', route: 'PUT /notes/:id' }, 'step_up');
  await expect({ ...suspicious, method: 'PUT', stepUp: { verified: true, authAgeSeconds: 0 } }, 'deny');
  await expect({ ...suspicious, service: 'admin' }, 'deny');
});
