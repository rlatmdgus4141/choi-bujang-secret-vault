// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  if (config.step === 2) {
    let empty = false;
    try {
      const data = await response.json();
      empty = response.ok && Array.isArray(data?.notes) && data.notes.length === 0
        && !JSON.stringify(data).includes(config.sampleMarker);
    } catch { /* JSON 형식 오류는 성공으로 기록하지 않습니다. */ }
    const api = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(15000),
    });
    let noteCount = 0;
    let valid = false;
    try {
      const data = await api.json();
      noteCount = Array.isArray(data?.notes) ? data.notes.length : 0;
      valid = api.ok && data?.sampleMarker === config.sampleMarker && noteCount === 4
        && data.notes.every(note => typeof note.title === 'string' && typeof note.content === 'string');
    } catch { /* 오류 응답 본문은 제출하지 않습니다. */ }
    return [
      { attackId: 'static_note_seed_read', expected: '현재 공개 data.json에는 메모와 1단계 확인 표시가 없음',
        observed: empty ? '비로그인 HTTP 200, 메모 0건과 1단계 확인 표시 없음 확인'
          : `정적 메모·확인 표시 제거 확인 실패 (HTTP ${response.status})` },
      { attackId: 'anonymous_server_api_read', expected: '2단계의 남은 약점: 공개 API가 가상 메모 네 건을 반환',
        observed: valid ? '비로그인 공개 API에서 가상 메모 4건 확인; 인증은 다음 단계 과제'
          : `가상 메모 네 건 확인 실패 (HTTP ${api.status}, 자료 ${noteCount}건)` },
    ];
  }
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
