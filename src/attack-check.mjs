import { readFileSync } from 'node:fs';
// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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
  if (config.step >= 3) {
    let empty = false;
    try {
      const data = await response.json();
      empty = response.ok && Array.isArray(data?.notes) && data.notes.length === 0
        && Object.keys(data).length === 1;
    } catch { /* 응답 본문을 기록하지 않습니다. */ }
    const attempts = [{ attackId: 'static_note_seed_read',
      expected: '현재 공개 data.json에는 빈 notes 배열만 있음',
      observed: empty ? 'HTTP 200, 메모 0건과 1단계 확인 표시 없음 확인'
        : `정적 자료 제거 확인 실패 (HTTP ${response.status})` }];
    for (const check of [
      { attackId: 'anonymous_note_read', method: 'GET' },
      { attackId: 'anonymous_note_create', method: 'POST' },
      { attackId: 'malformed_login_token', method: 'GET', headers: { Authorization: 'Bearer invalid' } },
      { attackId: 'anonymous_item_read', method: 'GET', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
      { attackId: 'anonymous_item_update', method: 'PUT', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
      { attackId: 'anonymous_item_delete', method: 'DELETE', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
    ]) {
      const api = await fetch(new URL(check.path ?? '/api/notes', app), {
        method: check.method, headers: check.headers, redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });
      let denied = false;
      try {
        const data = await api.json();
        denied = api.status === 401 && Object.keys(data).length === 1
          && typeof data.error === 'string';
      } catch { /* 오류 응답 원문은 제출하지 않습니다. */ }
      attempts.push({ attackId: check.attackId, expected: '유효한 로그인 없이 메모 접근 거부',
        observed: denied ? 'HTTP 401, 메모 없는 오류 응답 확인'
          : `인증 거부 확인 실패 (HTTP ${api.status})` });
    }
    if (config.step >= 5) {
      if (config.originalApiUrl !== new URL('/rest/v1/notes', config.identityProvider.issuer).href) {
        throw new Error('원본 자료 주소가 해당 Supabase 메모 경로와 다릅니다.');
      }
      // 브라우저에 이미 공개된 publishable key만 사용합니다. 사용자 JWT나 서버 키는 읽지 않습니다.
      const frontend = readFileSync(new URL('../public/auth.js', import.meta.url), 'utf8');
      const publicKey = frontend.match(/const publishableKey = '(sb_publishable_[A-Za-z0-9_-]+)'/u)?.[1];
      if (!publicKey) throw new Error('공개 키를 확인할 수 없어 원본 API 점검을 중단했습니다.');
      for (const method of ['GET', 'PATCH']) {
        const url = new URL(config.originalApiUrl);
        // id는 NOT NULL인 기본키입니다. PATCH 조건은 어떤 기존 행에도 일치하지 않습니다.
        url.search = method === 'GET' ? 'select=id&limit=1' : 'id=is.null';
        const direct = await fetch(url, { method, redirect: 'error',
          headers: { apikey: publicKey, ...(method === 'PATCH' ? { 'Content-Type': 'application/json' } : {}) },
          ...(method === 'PATCH' ? { body: JSON.stringify({ title: 'permission-check' }) } : {}),
          signal: AbortSignal.timeout(15000),
        });
        let denied = false;
        try {
          const data = await direct.json();
          denied = [401, 403].includes(direct.status) && data?.code === '42501';
        } catch { /* 응답 원문과 키는 기록하지 않습니다. */ }
        attempts.push({ attackId: method === 'GET' ? 'anon_original_read' : 'anon_original_update',
          expected: '공개 키만으로 원본 메모 테이블 직접 접근 거부',
          observed: denied ? `HTTP ${direct.status}, DB 권한 거부 확인; 자료·키 기록 없음`
            : `원본 권한 거부 확인 실패 (HTTP ${direct.status})` });
      }
    }
    return attempts;
  }
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
