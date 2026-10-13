# 8단계 자원 구역과 확인 범위

## 자원과 최종 API

| 자원 ID | 경로 | 허용 조건 |
|---|---|---|
| notes.personal | GET/POST /api/notes, GET/PUT/DELETE /api/notes/:id | 원본 도우미로 로그인 검증; 모든 조회·변경을 확인된 owner_id로 제한 |
| notices.instructor | GET /api/notices, GET /api/notices/:id | 검증된 로그인; 메모 테이블과 분리된 공지만 조회 |
| notices.instructor | POST /api/notices, PUT /api/notices/:id | 검증된 로그인 + Auth Admin 조회의 현재 app_metadata.vault_role이 instructor |

자료 응답은 기존 `{id,title,body}` 형태를 유지하고 응답 헤더 X-Resource-Id로 구역을 구별합니다.
메모 추가는 서버가 owner_id를 정하고, 수정·삭제는 ID와 소유자 조건을 같은 DB 요청에 적용합니다.
타인 메모와 없는 메모는 같은 404 오류입니다. URL의 다른 owner_id/role/action 선택자는 거부합니다.
정확한 경로 외의 중첩 경로·export·인코딩 우회는 거부하고, 선택적 id 쿼리는 경로 ID와 같아야 합니다.
메뉴·본문의 role, user_metadata, 토큰의 임의 강사 주장으로 권한을 부여하지 않습니다.
공지 수정은 매번 서버 Auth Admin에서 현재 권한을 조회하며, 조회 오류·사용자 불일치는 기본 거부합니다.
실제 계정에 강사 권한을 자동 부여하지 않았고 공지 시드도 넣지 않았습니다.
공지를 운영하려면 관리자가 공식 관리 수단에서 대상 사용자의 app_metadata.vault_role을 승인해야 합니다.
일반 사용자가 수정할 수 있는 user_metadata에 역할을 넣으면 안 됩니다.

## 판정기 계약의 한계

공식 docs/DECIDER_REQUEST.md의 18개 필드에는 메모 소유자와 강사 역할이 없습니다.
subjectId는 엔진 가명이며 Supabase 사용자 UUID가 아니므로 임의 비교나 하드코딩을 하지 않습니다.
resource_zones는 검증된 사용자·기기·service·method·path·route가 맞는 경로만 허용하는 1차 검사입니다.
notes와 notices의 서로 다른 서비스/경로 조합, 예약 동작 경로, 불명확한 경로는 기본 거부합니다.
원문 쿼리를 받을 수 없는 판정기는 queryLength가 0인 경로만 허용합니다. API는 같은 ID 선택만 허용합니다.
메모 allow는 소유자 검사 완료를 뜻하지 않으며 최종 API가 반드시 소유자 검사를 수행합니다.
강사 권한 계약이 없는 현재 엔진 경로에서는 공지 변경을 모두 거부합니다.
최종 공지 API의 강사 허용 기능은 구현했지만, 엔진을 거친 실제 강사 수정 실측은 미실행입니다.
기존 device_registered, step_up_required는 유지하고 공지 읽기도 복합 이상 접속 검사를 받습니다.

## DB

supabase/stage8-notices.sql을 적용했습니다. public.notes와 기존 4건은 보존했습니다.
새 public.notices는 0건, RLS 활성화, PUBLIC/anon/authenticated 직접 권한 없음입니다.
service_role은 SELECT/INSERT/UPDATE만 있으며 DELETE·TRUNCATE는 주지 않았습니다.
서버 비밀키는 기존 서버 환경변수에서만 읽습니다. 인증서·CA·개인키는 만들지 않았습니다.

## 실행한 검증 (2026-10-13)

- npm test: 49개 통과. A/B 각자 메모 CRUD, 교차 조회·수정·삭제 거부와 목록 분리 회귀 시험 포함.
- 새 API 시험: 경로/쿼리 구역 변경 거부, 학생 공지 수정 403, 위조 role/user_metadata/토큰 역할 무시.
- 공지 정상 생성·조회·수정, 없는 공지 404, 서버 역할 회수 후 403, 조회 장애 503: 모의 DB/Auth 시험 통과.
- 판정기 시험: 정확한 CRUD 경로 허용, 서비스/메서드 불일치·알 수 없는 경로·공지 변경 거부.
- npm run decider:test: 등록/미등록, 복합 이상/재확인 가상 요청 4개 통과. 실제 심판 판정 아님.
- npm run build -- --local 성공. npm run check:stage2의 현재 메모 본문·비밀값 일치 0건.
- 실제 DB 조회: notes 4건 유지, notices 0건, RLS 활성화와 직접 권한 회수 확인.
- 실제 A/B 브라우저 재확인과 강사 계정의 배포 API 정상 수정은 이번 단계에서 미실행.

## 재현과 제출

`npm test`와 `npm run decider:test`를 실행합니다.
기존 화면에서 A/B 각각 로그인하여 자기 메모 추가·수정·삭제를 확인합니다.
B로 A의 메모를 직접 조회/수정/삭제하면 404, 학생의 /api/notices/:id PUT은 403이어야 합니다.
시크릿 창의 /api/notes, /api/notices는 자료 없는 401 JSON 오류여야 합니다.
배포 커밋이 일치한 뒤 npm run bundle이 HTTP 13개 + 로컬 가상 사건 6개, 총 19개 점검을 실행합니다.
이 점검에는 실제 로그인 A/B·강사 시험을 포함했다고 주장하지 않습니다.

근거: https://supabase.com/docs/reference/javascript/auth-admin-getuserbyid
https://supabase.com/docs/guides/database/postgres/row-level-security#authjwt
