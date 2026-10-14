import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
// Stage 12 submission does not execute these checks. Live checks have their own command/report.
const stage12Plan = [
  ['static_note_seed_read', '공개 data.json에는 빈 메모 목록만 있음'],
  ['anonymous_notice_list', '로그인 없는 공지 목록 조회 거부'],
  ['anonymous_notice_update', '로그인 없는 공지 변경 거부'],
  ['anonymous_note_read', '로그인 없는 메모 목록 조회 거부'],
  ['anonymous_note_create', '로그인 없는 메모 추가 거부'],
  ['malformed_login_token', '잘못된 로그인 토큰 거부'],
  ['anonymous_item_read', '로그인 없는 개별 메모 조회 거부'],
  ['anonymous_item_update', '로그인 없는 개별 메모 변경 거부'],
  ['anonymous_item_delete', '로그인 없는 개별 메모 삭제 거부'],
  ['anon_original_read', '공개 키만으로 원본 메모 조회 거부'],
  ['anon_original_update', '공개 키만으로 원본 메모 변경 거부'],
  ['home_security_header', '첫 화면에 nosniff 보안 헤더가 있음'],
  ['browser_public_key_absent', '화면 코드에 데이터베이스 공개 키가 없음'],
  ['local_existing_device_risk_zone_detection', '기기·추가 확인·구역·탐지 가상 연동을 별도 확인'],
  ['backup_verified', '복구 사본의 무결성을 별도 확인'],
  ['post_restore_retest', '복구 후 정상·금지 요청을 별도 확인'],
  ['single_note_restore_matches', '본인 메모 한 건 복구 후 ID·소유자·해시 대조'],
  ['restore_preserves_other_records', '복구 시 다른 자료와 감사 기록 보존'],
  ['app_approval_and_request_signatures', '기기 승인·요청 서명·변조 거부를 별도 확인'],
  ['operations_evidence_and_installable_app', '작전실·설치 화면 근거를 별도 확인하며 공식 41종 결과를 만들지 않음'],
];

function checkedApp(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try { app = new URL(config.publicAppUrl); } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  return app;
}

export async function runAttackChecks(config, options = {}) {
  if (config.step !== 12) return runLiveAttackChecks(config, options);
  checkedApp(config);
  // No fetch, credentials, DB access or imported live report in this submission path.
  return stage12Plan.map(([attackId, expected]) => ({ attackId, expected, observed: 'not_run' }));
}

export async function runLiveAttackChecks(config, { requirePass = false } = {}) {
  // Keep request metadata and the wire header equal to the reported attempt ID.
  // This identifies a check; it never grants authentication or device approval.
  const request = (attackId, url, init = {}) => fetch(url, {
    ...init, attackId,
    headers: { ...init.headers, 'x-aleph-attack-id': attackId },
  });
  // 성공 여부는 응답에서 판정한 boolean으로만 결정합니다. 제출용 문구는 판정에 쓰지 않습니다.
  const finish = (attempts, passed) => {
    if (requirePass) {
      const failed = attempts.filter((_, index) => passed[index] !== true && attempts[index].observed !== 'not_run');
      if (failed.length) throw new Error(`실제 배포 자기 점검 실패: ${failed.map(item => item.attackId === 'operations_evidence_and_installable_app' ? `${item.attackId} (${item.observed})` : item.attackId).join(', ')}`);
    }
    return attempts;
  };
  const app = checkedApp(config);
  const response = await request(config.step >= 2 ? 'static_note_seed_read' : 'anonymous_note_read', new URL('/data.json', app), {
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
    const passed = [empty];
    for (const check of [
      ...(config.step >= 8 ? [
        { attackId: 'anonymous_notice_list', method: 'GET', path: '/api/notices' },
        { attackId: 'anonymous_notice_update', method: 'PUT', path: '/api/notices/00000000-0000-4000-8000-000000000000' },
      ] : []),
      { attackId: 'anonymous_note_read', method: 'GET' },
      { attackId: 'anonymous_note_create', method: 'POST' },
      { attackId: 'malformed_login_token', method: 'GET', headers: { Authorization: 'Bearer invalid' } },
      { attackId: 'anonymous_item_read', method: 'GET', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
      { attackId: 'anonymous_item_update', method: 'PUT', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
      { attackId: 'anonymous_item_delete', method: 'DELETE', path: '/api/notes/00000000-0000-4000-8000-000000000000' },
    ]) {
      if (!['GET', 'HEAD'].includes(check.method)) {
        attempts.push({ attackId: check.attackId, expected: '유효한 로그인 없이 메모 접근 거부 (쓰기 요청은 격리 환경에서 미실행)', observed: 'not_run' });
        passed.push(null);
        continue;
      }
      const api = await request(check.attackId, new URL(check.path ?? '/api/notes', app), {
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
        observed: denied ? (config.step >= 10 && check.attackId === 'anonymous_note_create'
          ? '메모 추가·복구 POST 모두 HTTP 401 JSON, 자료 없는 오류 응답 확인'
          : 'HTTP 401, 메모 없는 오류 응답 확인')
          : `인증 거부 확인 실패 (HTTP ${api.status})` });
      passed.push(denied);
    }
    if (config.step >= 5) {
      if (config.originalApiUrl !== new URL('/rest/v1/notes', config.identityProvider.issuer).href) {
        throw new Error('원본 자료 주소가 해당 Supabase 메모 경로와 다릅니다.');
      }
      // 서버 Auth 함수의 공개 키만 사용합니다. 사용자 JWT나 서버 전용 키는 읽지 않습니다.
      const authServer = readFileSync(fileURLToPath(new URL('../api/auth.js', import.meta.url)), 'utf8');
      const publicKey = authServer.match(/const publishableKey = '(sb_publishable_[A-Za-z0-9_-]+)'/u)?.[1];
      if (!publicKey) throw new Error('공개 키를 확인할 수 없어 원본 API 점검을 중단했습니다.');
      for (const method of ['GET', 'PATCH']) {
        if (method === 'PATCH') {
          attempts.push({ attackId: 'anon_original_update', expected: '원본 직접 수정 거부 (격리 환경에서 쓰기 요청 미실행)', observed: 'not_run' });
          passed.push(null);
          continue;
        }
        const url = new URL(config.originalApiUrl);
        // id는 NOT NULL인 기본키입니다. PATCH 조건은 어떤 기존 행에도 일치하지 않습니다.
        url.search = method === 'GET' ? 'select=id&limit=1' : 'id=is.null';
        const direct = await request(method === 'GET' ? 'anon_original_read' : 'anon_original_update', url, { method, redirect: 'error',
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
        passed.push(denied);
      }
      const home = await request('home_security_header', new URL('/', app), { redirect: 'error', signal: AbortSignal.timeout(15000) });
      const protectedHome = home.ok && home.headers.get('x-content-type-options') === 'nosniff';
      attempts.push({ attackId: 'home_security_header', expected: '첫 화면 응답에 nosniff 보안 헤더가 있음',
        observed: protectedHome ? 'HTTP 200, X-Content-Type-Options: nosniff 확인'
          : `첫 화면 보안 헤더 확인 실패 (HTTP ${home.status})` });
      passed.push(protectedHome);
      const browserHome = await request('browser_public_key_absent', new URL('/', app), { redirect: 'error', signal: AbortSignal.timeout(15000) });
      const html = await browserHome.text();
      const paths = new Set();
      for (const match of html.matchAll(/src=["']([^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']/gu)) {
        const url = new URL(match[1], app);
        if (url.origin === app.origin) paths.add(url.href);
      }
      let noClientKey = browserHome.ok && paths.size > 0 && !html.includes(publicKey);
      for (const path of paths) {
        const script = await request('browser_public_key_absent', path, { redirect: 'error', signal: AbortSignal.timeout(15000) });
        const text = await script.text();
        noClientKey &&= script.ok && !text.includes(publicKey)
          && !/\bsb_publishable_[A-Za-z0-9_-]{8,}|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/u.test(text);
      }
      attempts.push({ attackId: 'browser_public_key_absent', expected: '첫 화면과 화면 스크립트에 Supabase 공개 키가 없음',
        observed: noClientKey ? '첫 화면·화면 스크립트에서 Supabase 공개 키 없음 확인'
          : '화면 코드의 공개 키 제거 확인 실패' });
      passed.push(noClientKey);
    }
    // API-handler integration uses npm packages/WebCrypto and writes synthetic state.
    // Run it separately with ops:check/recovery:check/device:check, never in the bundle sandbox.
    const skipped = [
      ...(config.step >= 6 ? [['local_existing_device_risk_zone_detection', '기기·위험·구역·탐지 통합 시험은 별도 실행']] : []),
      ...(config.step >= 10 ? [
        ['backup_verified', '사본 재검증은 recovery:check에서 별도 실행'],
        ['post_restore_retest', '복원 뒤 정상·금지 요청 재시험은 별도 실행'],
        ['single_note_restore_matches', '한 건 복구 쓰기 시험은 격리 환경에서 미실행'],
        ['restore_preserves_other_records', '복구 후 다른 자료 보존 시험은 별도 실행'],
      ] : []),
      ...(config.step >= 11 ? [['app_approval_and_request_signatures', '승인·서명·변조 시험은 device:check에서 별도 실행']] : []),
    ];
    for (const [attackId, expected] of skipped) {
      attempts.push({ attackId, expected, observed: 'not_run' });
      passed.push(null);
    }
    if (config.step >= 11) {
      const appAttackId = config.step >= 12 ? 'operations_evidence_and_installable_app' : 'installable_public_offline_shell';
      const manifest = await request(appAttackId, new URL('/manifest.webmanifest',app), {redirect:'error',signal:AbortSignal.timeout(15000)});
      let installable = false;
      const installChecks = { manifest: false, icons: false, worker: false, offline: false };
      try {
        const data = await manifest.json();
        installable = manifest.ok && data.start_url === '/' && data.scope === '/'
          && data.display === 'standalone' && data.icons?.length === 2;
        installChecks.manifest = installable;
        let iconsValid = Array.isArray(data.icons) && data.icons.length === 2;
        for (const icon of data.icons ?? []) {
          const url = new URL(icon.src,app);
          if(url.origin !== app.origin){iconsValid=false;break;}
          // HEAD verifies the public icon without the sandbox's optional binary-body API.
          const response = await request(appAttackId, url,{method:'HEAD',redirect:'error',signal:AbortSignal.timeout(15000)});
          const mediaType = response.headers.get('content-type')?.split(';')[0].trim().toLowerCase();
          iconsValid &&= response.status === 200 && mediaType === 'image/png';
        }
        installChecks.icons = iconsValid;
        installable &&= iconsValid;
      } catch { installable = false; }
      const worker = await request(appAttackId, new URL('/sw.js',app),{redirect:'error',signal:AbortSignal.timeout(15000)});
      const source = await worker.text();
      const offline = await request(appAttackId, new URL('/offline.html',app),{redirect:'error',signal:AbortSignal.timeout(15000)});
      installChecks.worker = worker.ok && source.includes("url.pathname.startsWith('/api/')")
        && source.includes('/offline.html') && !source.includes('cache.put');
      installChecks.offline = offline.ok;
      installable &&= installChecks.worker && installChecks.offline;
      attempts.push({attackId:'installable_public_offline_shell',
        expected:'manifest·아이콘·오프라인 안내가 열리고 보호 API는 캐시하지 않음',
        observed:installable?'실제 manifest·아이콘 2개 HEAD 200/image/png·오프라인 안내·API 캐시 제외 확인; 바이너리 본문 미검사'
          :'설치형 앱 공개 파일 확인 실패'});
      passed.push(installable);
      if(config.step>=12){
        const response=await request(appAttackId, new URL('/api/operations',app),{redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
        const metadata=await response.json();
        const evidence=await request(appAttackId, new URL('/operations-verification.json',app),{redirect:'error',cache:'no-store',signal:AbortSignal.timeout(15000)});
        const report=await evidence.json();
        const operationsChecks = {
          api_status: response.status === 200,
          request_id: Boolean(response.headers.get('x-vault-request-id')),
          checked_at: Number.isFinite(Date.parse(response.headers.get('x-vault-checked-at'))),
          metadata_step: metadata.step === 12,
          engine_source: metadata.engine?.name === 'ALEPH SDP 엔진',
          official_unexecuted: metadata.officialAttacks?.verified === 0 && metadata.officialAttacks?.status === 'unexecuted',
          report_status: evidence.ok,
          report_commit: report.commit === metadata.commit,
          report_result: report.passed === true,
        };
        const valid = Object.values(operationsChecks).every(Boolean);
        const failures = [...Object.entries(installChecks), ...Object.entries(operationsChecks)]
          .filter(([, passed]) => !passed).map(([name]) => name);
        attempts[attempts.length-1]={attackId:'operations_evidence_and_installable_app',
          expected:'설치형 앱 유지, 작전실 API·서버 요청 근거·가상 통합 시험·공식 41종 미실행 구분',
          observed:valid&&installable?'실제 작전실 API HTTP 200와 요청 ID/시각, 설치 파일 및 아이콘 HEAD 200/image/png 확인; 바이너리 본문 미검사; 배포 가상 보고서 조회(재실행 아님); 공식 41종 미확인'
            :`작전실/설치 근거 확인 실패: ${failures.join(', ')}`};
        passed[passed.length-1]=valid&&installable;
      }
    }
    return finish(attempts, passed);
  }
  if (config.step === 2) {
    let empty = false;
    try {
      const data = await response.json();
      empty = response.ok && Array.isArray(data?.notes) && data.notes.length === 0
        && !JSON.stringify(data).includes(config.sampleMarker);
    } catch { /* JSON 형식 오류는 성공으로 기록하지 않습니다. */ }
    const api = await request('anonymous_server_api_read', new URL('/api/notes', app), {
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
    return finish([
      { attackId: 'static_note_seed_read', expected: '현재 공개 data.json에는 메모와 1단계 확인 표시가 없음',
        observed: empty ? '비로그인 HTTP 200, 메모 0건과 1단계 확인 표시 없음 확인'
          : `정적 메모·확인 표시 제거 확인 실패 (HTTP ${response.status})` },
      { attackId: 'anonymous_server_api_read', expected: '2단계의 남은 약점: 공개 API가 가상 메모 네 건을 반환',
        observed: valid ? '비로그인 공개 API에서 가상 메모 4건 확인; 인증은 다음 단계 과제'
          : `가상 메모 네 건 확인 실패 (HTTP ${api.status}, 자료 ${noteCount}건)` },
    ], [empty, valid]);
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
  return finish([{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }], [visible]);
}
