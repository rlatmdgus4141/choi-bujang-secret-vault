import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { respond, createXdrGate } from '../xdr/web-injection/respond.mjs';

// Training replay only. Keep the original fixture bytes unchanged and use its own clock.
export async function replayWebInjection({ root, rulePath, logPath }) {
  const fixture = JSON.parse(await readFile(new URL('xdr/fixtures/web-injection.json', root), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection' || !Array.isArray(fixture.alerts)) {
    throw new Error('invalid_web_injection_fixture');
  }
  const alerts = [...fixture.alerts].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const counts = { block: 0, alert: 0, record: 0 };
  const trustedSources = new WeakMap();
  let replayTime = 0;
  let baseCalls = 0;
  let rulesAdded = 0;
  let normalEvents = 0;
  let normalBlocked = 0;
  let blockedCandidatesDenied = 0;
  const base = request => {
    baseCalls++;
    return { schema: 'aleph.decision.v1', requestId: request.requestId, decision: 'allow', reasonCode: 'fixture_allow', ruleIds: ['fixture.base'] };
  };
  const gate = createXdrGate(base, {
    trustedSourceIpForRequest: request => trustedSources.get(request), rulePath, clock: () => replayTime,
    denyResponse: (request, rule) => ({ schema: 'aleph.decision.v1', requestId: request.requestId,
      decision: 'deny', reasonCode: 'fixture_deny', ruleIds: [rule.id] }),
  });
  for (const alert of alerts) {
    replayTime = Date.parse(alert.timestamp);
    const out = await respond(alert, { rulePath, logPath, now: replayTime });
    counts[out.decision.action]++;
    if (out.addedRule) rulesAdded++;
    const request = Object.freeze({ schema: 'aleph.decision.v1', requestId: alert.id });
    trustedSources.set(request, alert.data.srcip);
    const decision = await gate(request);
    const ids = Array.isArray(alert.rule.mitre) ? alert.rule.mitre : [];
    const normal = alert.rule.level <= 3 && ids.length === 0
      && /조회|화면|새로고침/u.test(alert.rule.description);
    if (normal) { normalEvents++; if (decision.decision === 'deny') normalBlocked++; }
    if (out.decision.action === 'block' && decision.decision === 'deny') blockedCandidatesDenied++;
  }
  return { schema: 'aleph.xdr.replay.v1', simulated: true, counts, rulesAdded,
    blockedCandidatesDenied, normalEvents, normalBlocked, baseCalls,
    integration: 'isolated_gate_with_fixture_base_policy', liveEngineConnected: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv[2] !== 'web-injection') throw new Error('web-injection만 재생할 수 있습니다.');
    const root = new URL('../', import.meta.url);
    const report = await replayWebInjection({ root,
      rulePath: new URL('xdr/runtime/web-injection-deny-rules.json', root), logPath: new URL('xdr/alerts.log', root) });
    console.log(JSON.stringify(report));
    if (report.normalBlocked !== 0 || report.blockedCandidatesDenied !== report.counts.block) process.exitCode = 1;
  } catch { console.error('XDR 시험 재생 실패: 경보·추가 규칙 형식을 확인하세요.'); process.exitCode = 1; }
}
