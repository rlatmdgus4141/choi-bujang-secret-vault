import { isDeepStrictEqual } from 'node:util';

// 오류에는 필드 이름만 남깁니다. 응답 원문이나 실제 설정값은 출력하지 않습니다.
export function assertDeploymentMetadata(identity, config, commit) {
  const expected = {
    schema: 'aleph.defense.deployment.v1', step: config.step,
    repoUrl: config.repoUrl, commit, judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    ...(config.step >= 3 ? { identityProvider: config.identityProvider,
      allowedRoutes: config.allowedRoutes } : {}),
    ...(config.step >= 5 ? { originalApiUrl: config.originalApiUrl } : {}),
  };
  if (!identity || typeof identity !== 'object' || Array.isArray(identity)) {
    throw new Error('배포 식별 정보가 JSON 객체가 아닙니다.');
  }
  const mismatched = Object.keys(expected).filter(field =>
    !isDeepStrictEqual(identity[field], expected[field]));
  if (mismatched.length) {
    throw new Error(`배포 식별 정보 불일치: ${mismatched.join(', ')}. 현재 커밋의 배포 완료를 확인해 주세요.`);
  }
}

export async function verifyDeployment(config, commit, { fetchImpl = fetch } = {}) {
  let app;
  try { app = new URL(config.publicAppUrl); } catch {
    throw new Error('배포 확인에는 실제 HTTPS 자료실 주소가 필요합니다.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/') {
    throw new Error('배포 확인에는 실제 HTTPS 자료실 주소가 필요합니다.');
  }
  const response = await fetchImpl(new URL('/aleph.json', app), {
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(15000),
  });
  if (response.status !== 200) throw new Error(`배포 식별 정보 요청 실패 (HTTP ${response.status})`);
  let identity;
  try { identity = await response.json(); } catch {
    throw new Error('배포 식별 정보 응답이 올바른 JSON이 아닙니다.');
  }
  assertDeploymentMetadata(identity, config, commit);
}
