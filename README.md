# BYTE BACK 방어전 자료실 R5

## 현재 단계: 4단계 제작 2 · API 소유자 검사

- 저장소: https://github.com/rlatmdgus4141/choi-bujang-secret-vault
- 브랜치: defense-r5
- 배포: https://choi-bujang-secret-vault-rosy.vercel.app
- Supabase: choi-bujang-secret-vault
- 이전 결과: 1단계 100점, 2단계 90점, 3단계 90점 방어 성공(사용자 확인).
- 현재는 API 소유자 검사까지 구현했습니다. DB 권한·RLS SQL은 제작 3에서 사용자가 검토·실행합니다.

Supabase Auth 이메일·비밀번호 로그인과 로그아웃을 제공합니다.
공식 SDK 2.117.2를 package-lock.json에 고정하고 빌드 때 public/vendor로 복사합니다.
브라우저에는 Project URL과 publishable key만 포함합니다.
비밀번호는 공식 SDK에 전달한 뒤 입력창에서 지우며 직접 저장·기록하지 않습니다.
세션 저장과 갱신은 SDK에 맡기고 JWT를 화면·로그·Git·제출 묶음에 출력하지 않습니다.

## 서버 인증과 메모 API

api/notes.js는 원본 src/verify-login.mjs의 createLoginVerifier를 사용합니다.
도우미를 수정하거나 새로 만들지 않았으며 원본 Git blob 해시도 시험합니다.
학생 토큰은 Supabase SDK getClaims로 검증하고 발급자·대상·역할·사용자 ID·만료를 확인합니다.
심판 토큰은 원본 judgeIssuer의 공개키로 서명과 발급 조건을 검증합니다.
DB 접근은 검증 결과의 userId가 있을 때만 수행합니다.
목록과 개별 메모 GET·PUT·DELETE 모두 owner_id가 검증한 userId와 일치해야 합니다.
조회·수정·삭제의 SQL 조건에 메모 ID와 owner_id를 함께 넣어 원자적으로 처리합니다.
PUT은 기존 행의 소유자 조건을 적용하고 새 행의 owner_id도 검증한 userId로 고정합니다.
본문에 다른 owner_id를 지정한 POST·PUT은 403으로 거부합니다.
타인 소유·소유자 없음·존재하지 않는 메모는 모두 자료 없는 404로 응답합니다.
클라이언트의 userId·role·owner_id는 신원 확인이나 소유자 지정에 사용하지 않습니다.

| 메서드 | 경로 | 응답 |
| --- | --- | --- |
| GET | /api/notes | 로그인한 사용자의 메모 배열, 각 항목은 {id,title,body} |
| POST | /api/notes | {id,title,body} 입력, id 생략 시 서버 UUID 생성, 201 {id} |
| GET | /api/notes/:id | 200 {id,title,body}, 없는 메모는 404 |
| PUT | /api/notes/:id | {title,body}로 수정, 200 {id,title,body}, 없는 메모는 404 |
| DELETE | /api/notes/:id | 200 {id}, 삭제 후 GET은 404 |

api/notes/[id].js는 같은 인증·자료 처리 함수를 연결합니다.
모든 메서드는 토큰이 없거나 검증에 실패하면 메모 없는 HTTP 401로 거부합니다.
정상 로그인 후 잘못된 입력은 400, 중복 ID는 기존 자료를 덮어쓰지 않고 409,
지원하지 않는 메서드는 405입니다. 서버 설정 오류는 503, DB 오류는 상세 없는 502입니다.
응답에 Cache-Control: no-store와 Vary: Authorization을 지정합니다.
제목은 1~200자, 본문은 20,000자 이내이며 화면은 textContent로 메모를 표시합니다.

aleph.config.json의 step은 4입니다. API 메서드·경로와 응답 계약은 3단계 그대로 유지합니다.
identityProvider에는 해당 Supabase의 /auth/v1 발급자, audience authenticated,
/.well-known/jwks.json 공개키 주소를 기록했습니다. 실제 키는 포함하지 않습니다.
allowedRoutes에는 위 GET·POST·PUT·DELETE 경로를 method/path로 기록했습니다.
빌드된 /aleph.json에도 발급자와 경로, 실제 Vercel Git 커밋을 함께 기록합니다.
judgeIssuer는 시작 틀 값을 유지합니다.

## DB와 기존 자료 보존

public.notes는 owner_id uuid를 가지며 auth.users 외래키는 없습니다.
새 메모의 owner_id는 서버가 검증한 userId로 저장합니다.
기존 가상 메모 네 건의 제목과 본문은 보존했습니다.
사용자가 제작 1 SQL을 실행하여 첫 세 건은 A, 네 번째는 B에 배정했습니다.
이후 읽기 전용 조회로 A 3건·B 1건을 확인했습니다.
목록은 owner_id가 로그인한 userId인 메모만 반환합니다.
position은 DB identity 순번으로 생성하여 동시 추가 때 순번 충돌을 피합니다.

RLS를 유지하고 PUBLIC·anon·authenticated의 테이블과 순번 시퀀스 권한을 제거했습니다.
서버 역할 service_role에는 SELECT·INSERT·UPDATE·DELETE와 순번 사용 권한을 부여했습니다.
자동 RLS 보조 함수의 공개 실행 권한 제거도 유지합니다.
브라우저의 DB 직접 접근을 전부 거부하므로 RLS 정책이 없다는 INFO는 의도된 상태입니다.
DB의 구조와 권한은 supabase/schema.sql에 있으며 메모 본문·실제 키는 포함하지 않습니다.
새 프로젝트에서 이 파일로 구조를 재현할 수 있습니다. 기존 내용을 덮어쓰거나 삭제하지 않습니다.
이 SQL은 기존 메모의 소유자를 자동 변경하지 않습니다.

## API 검사와 DB 정책

3단계에서 남겨 둔 개별 메모의 타인 접근을 이번 API 수정으로 막았습니다.
service_role은 RLS를 우회하므로 API의 명시적인 소유자 조건이 반드시 필요합니다.
현재 authenticated의 직접 DB 권한은 아직 회수된 상태입니다.
본인 행만 허용하는 GRANT와 SELECT·INSERT·UPDATE·DELETE RLS 정책은 제작 3의 별도 SQL 과제입니다.
이번 제작 2에서는 DB 권한과 정책을 변경하지 않았습니다. supabase/schema.sql도 기존 상태입니다.
실제 배포의 A/B 교차 접근 결과는 사용자 화면 확인과 심판 판정으로 별도 확인해야 합니다.
로컬 시험을 실제 로그인 계정으로 수행한 배포 시험이라고 주장하지 않습니다.

현재 파일의 메모 제거만으로 과거 노출이 해소되지는 않습니다.
이전 공개 Git 커밋, 기존 Vercel 배포, 포크·캐시·내려받은 사본은 남을 수 있습니다.
이번 단계는 기존 공개 이력을 삭제하거나 과거 노출을 해결했다고 주장하지 않습니다.

## 실행 및 설정

```sh
npm ci
npm run build -- --local
npm test
npm run check:stage2 -- --deployed
```

check:stage2라는 명령 이름을 유지하며, 현재 단계의 정적 메모·비밀값 노출과 배포 커밋을 확인합니다.
로컬 빌드는 정적 산출물 생성이며 실제 API 실행이나 배포 성공의 증거가 아닙니다.
서버 환경변수 이름은 .env.example에 빈 값으로 제공합니다.
SUPABASE_URL과 SUPABASE_SECRET_KEY는 Vercel Settings → Environment Variables의
Production에 등록합니다. 서버 키는 Secret 유형이며 공식 입력란에만 넣습니다.
GitHub defense-r5 변경은 연결된 Vercel Production으로 배포됩니다.

계정은 Supabase Authentication → Users에서 관리합니다.
A 계정 비밀번호는 로그인 화면에만 입력하고 에이전트에게 공유하지 않습니다.
A 로그인에는 기존 메모 세 건, B 로그인에는 한 건과 메모 입력란이 나타나야 합니다.
두 계정에서 각각 새 시험 메모를 추가·수정·삭제해 정상 기능을 확인합니다.
새 가상 메모 하나를 추가하고 그 메모만 수정·삭제하여 동작을 확인합니다.
로그아웃하면 메모와 작성 내용이 지워지고 로그인 폼이 나타나야 합니다.
시크릿 창의 /api/notes 또는 개별 메모 경로는 메모 없는 401 오류여야 합니다.

## 검증 기록

- 제작 1 로그인·로그아웃, 제작 2 서버 인증 후 네 메모 표시: 사용자 화면 확인 완료.
- 4단계 제작 2 로컬 빌드와 회귀·인증·CRUD·소유자 시험 총 19개: 통과.
- 정상 서명, 위조 서명, 만료, 잘못된 발급자·대상·역할·사용자 ID, 무토큰 거부 시험: 통과.
- API 시험: 서버 UUID 생성, 지정 UUID, 서버 확인 owner_id, 내 목록, 개별 조회·수정·삭제,
  삭제 후 404, 중복 ID 충돌, 잘못된 입력 거부, A/B 상대 메모 조회·수정·삭제 거부,
  소유자 변경 거부, 헤더·쿼리의 사용자 정보 무시, 심판 소유·소유자 없는 행 기본 거부.
- 실제 DB service_role로 추가·조회·수정·삭제 시험: 통과. 시험 트랜잭션은 롤백했습니다.
- DB 확인: 기존 메모 4건, A 3건·B 1건. 제작 2에서는 DB를 읽기만 했습니다.
- SDK/DOM 모의 화면 시험: 추가·수정·삭제 흐름과 로그아웃 시 화면·작성 내용 제거 통과.
- 제작 3 실제 A 계정 브라우저 CRUD: 사용자 확인 완료. 심판 조건 7개 충족, 최종 90점.
- 4단계 제작 2 배포의 실제 A/B 브라우저 CRUD: 사용자 확인 대기.
- 브라우저 자동 검증은 실행 환경 준비 실패로 미실행입니다.
- 현재 파일 31개 검색: 기존 가상 메모 본문·비밀값 일치 0건.
- Supabase 보안 점검: RLS 정책 없음 INFO, Auth 유출 비밀번호 검사 비활성화 WARN 1건.
  후자는 별도 Auth 설정이며 이 단계의 토큰 검증 결과와 구분합니다.
  안내: https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection

## 저장점과 제출

현재는 4단계 제작 2 중간 커밋입니다. 제작 3 SQL 검토·적용과 권한 확인 뒤
4단계 저장점으로 커밋하고 npm run bundle을 실행합니다. 아직 최종 제출하지 않습니다.
자기 점검은 정적 자료, 무토큰 목록·추가·개별 조회·수정·삭제, 잘못된 토큰 조회를 실제 요청합니다.
실제 HTTP 상태와 자료 없는 오류 여부만 기록하며 토큰·메모 본문은 묶음에 넣지 않습니다.
만료·위조·다른 대상 토큰의 로컬 시험은 실제 심판 판정으로 기록하지 않습니다.
bundle-notes.json과 artifacts/submission.json은 Git에서 제외합니다.
이전 단계 제출 묶음은 현재 4단계의 증거가 아니므로 최종 저장점에서 새 묶음을 생성합니다.
심판 점수는 포털에 제출한 뒤 확인합니다. src/decider.mjs와 src/detect.mjs는 보존합니다.
