import { createHash, randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Local practice requests use the engine's public input shape. The judge sends and times its own events.
const request = (signals, recentEvents) => ({
  schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class_fixture',
  projectId: 'project_fixture', subjectId: 'learner_fixture', deviceId: 'a'.repeat(16),
  service: 'notes', method: 'GET', path: '/notes/demo', route: 'GET /notes/:id',
  queryLength: 0, querySha256: createHash('sha256').update('').digest('hex'),
  at: new Date().toISOString(), policyRevision: 1, deviceRegistered: true,
  stepUp: { verified: false, authAgeSeconds: null }, recentEvents, signals,
});
export function fixtureRequests() {
  return {
    normal: request({ source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 }, []),
    suspicious: request({ source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
      [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }]),
  };
}
const check = (input, output, ruleIds) => output && typeof output === 'object' && !Array.isArray(output)
  && Object.keys(output).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
  && output.schema === 'aleph.decision.v1' && output.requestId === input.requestId
  && ['allow', 'deny', 'step_up'].includes(output.decision)
  && typeof output.reasonCode === 'string' && /^[a-z][a-z0-9_]{0,63}$/u.test(output.reasonCode)
  && Array.isArray(output.ruleIds) && output.ruleIds.length > 0
  && output.ruleIds.every(id => ruleIds.includes(id));

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { normal, suspicious } = fixtureRequests();
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    if (typeof decide !== 'function' || !Array.isArray(RULE_IDS)) throw new Error('src/decider.mjs에서 decide 함수와 RULE_IDS를 내보내야 합니다.');
    // These are local engine-contract fixtures, never evidence of a real login.
    const rechecked = { ...suspicious, requestId: randomUUID(), at: new Date().toISOString(),
      stepUp: { verified: true, authAgeSeconds: 60 } };
    const expired = { ...suspicious, requestId: randomUUID(), at: new Date().toISOString(),
      stepUp: { verified: true, authAgeSeconds: 901 } };
    const checks = [
      ['정상 사건', normal, 'allow', 'approved'],
      ['복합 이상 사건 · 확인 전', suspicious, 'step_up', 'step_up_required'],
      ['같은 주체·기기 재확인 후', rechecked, 'allow', 'approved'],
      ['추가 확인 유효시간 만료', expired, 'step_up', 'step_up_required'],
    ];
    for (const [name, request, expected, reason] of checks) {
      const response = await decide(request);
      if (!check(request, response, RULE_IDS)) throw new Error('판정기 응답 5항목·요청 ID·규칙 이름이 맞지 않습니다.');
      process.stdout.write(`${name}: ${response.decision} · ${response.reasonCode}\n`);
      if (response.decision !== expected || response.reasonCode !== reason) {
        throw new Error('정상·복합 이상·재확인·만료 판정이 기대 결과와 다릅니다.');
      }
    }
    process.stdout.write('가상 사건 연습입니다. 실제 재로그인·자료 차단 실측과 심판 판정은 미실행입니다.\n');
  } catch (error) {
    process.stderr.write(`가상 사건 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
