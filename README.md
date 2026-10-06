# BYTE BACK 방어전 자료실 R5

## 현재 단계: 5단계 저장점 · 자료 요청을 서버 한곳으로 모읍니다

- 저장소: https://github.com/rlatmdgus4141/choi-bujang-secret-vault
- 브랜치: defense-r5
- 배포: https://choi-bujang-secret-vault-rosy.vercel.app
- Supabase: choi-bujang-secret-vault
- 이전 결과: 1단계 100점, 2~4단계 각 90점. 5단계 첫 제출은 조건 7개 충족, 완결성 가점 1개, 80점(사용자 확인).
- 사용자가 5단계 권한 회수 SQL을 검토·실행했습니다. 실제 DB에서 두 역할의 직접 권한 회수와 서버 CRUD 권한 보존을 확인했습니다.

Supabase Auth 이메일·비밀번호 로그인과 로그아웃을 제공합니다.
공식 SDK 2.117.2를 package-lock.json에 고정하고 빌드 때 public/vendor로 복사합니다.
브라우저에는 Project URL만 포함하며 Supabase 공개 키도 api/auth.js 서버 함수에만 둡니다.
공식 SDK의 global.fetch를 통해 로그인·세션 갱신·로그아웃 요청을 /api/auth로 전달합니다.
비밀번호는 공식 SDK에 전달한 뒤 입력창에서 지우며 직접 저장·기록하지 않습니다.
세션 저장과 갱신은 SDK에 맡기고 JWT를 화면·로그·Git·제출 묶음에 출력하지 않습니다.

## 5단계 변경 및 검증 보완

브라우저의 Supabase 직접 메모 호출은 없습니다. Auth 호출은 유지하며
메모 읽기·추가·수정·삭제는 모두 /api/notes와 /api/notes/:id를 사용합니다.
public.notes의 PUBLIC·anon·authenticated 직접 테이블 권한을 회수했습니다.
서버 역할 service_role의 기존 권한과 로그인·소유자 검사는 보존했습니다.
원본 자료 경로는 https://nsqtwulghnijprefvfud.supabase.co/rest/v1/notes 입니다.
aleph.config.json과 배포 식별 정보의 originalApiUrl에 쿼리 없는 HTTPS 경로를 기록합니다.
Project URL은 공개 설정이며 공개 키와 서버 전용 키는 브라우저에 없습니다.
서버 전용 키, 원본 로그인 검증 도우미, API 소유자 검사, Supabase Auth 설정은 변경하지 않았습니다.
추가 보완은 점검 실패 시 제출 생성 중단, 배포 설정 전체 대조, DB 권한 점검의 재현성입니다.
사용자가 공개된 5단계 가점 기준을 제공했습니다. 허용 경로, 첫 화면 보안 헤더, 화면 코드의 공개 키 제거를 각각 확인합니다.

## 공개된 5단계 가점 조건

기본 조건 통과 70점에 아래 조건마다 10점이 추가됩니다(사용자가 제공한 안내).

| 조건 | 구현 | 다시 확인하는 방법 |
| --- | --- | --- |
| /aleph.json의 allowedRoutes가 비어 있지 않음 | 기존 메모 API 경로 5개 유지 | 배포 식별 정보 대조 |
| 첫 화면 보안 헤더 | vercel.json의 전체 경로에 X-Content-Type-Options: nosniff | npm run check:stage2 -- --deployed |
| 화면 코드에 Supabase 공개 키 없음 | 공개 키는 api/auth.js에서만 사용 | 배포 화면·스크립트 검사 |

인증 전달 함수는 이메일 로그인과 토큰 갱신, 본인 사용자 조회, 현재 세션 로그아웃만 허용합니다.
자료·관리자·임의 주소 전달은 거부하며 키를 설정 응답으로 보내지 않습니다.
브라우저의 server-auth 문자열은 SDK 초기화용 표식이고 Supabase에서 발급한 키가 아닙니다.
SDK가 비밀번호와 세션을 처리하며 토큰을 직접 생성하지 않습니다.
세션 저장 키를 바꾸지 않아 기존 로그인은 동일 프로젝트의 세션으로 이어집니다.
가점 조건 구현·자기 점검과 공식 점수 확정은 구분합니다. 최종 점수는 재제출 판정으로 확인합니다.

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

aleph.config.json의 step은 5입니다. API 메서드·경로와 응답 계약은 3단계 그대로 유지합니다.
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

RLS를 켜고 PUBLIC·anon·authenticated의 기존 테이블 권한을 먼저 회수했습니다.
4단계에서 부여했던 authenticated의 SELECT·INSERT·UPDATE·DELETE도 5단계에서 회수했습니다.
SELECT·DELETE의 USING, INSERT의 WITH CHECK, UPDATE의 USING과 WITH CHECK는
모두 (select auth.uid()) = owner_id를 검사합니다. 정책 대상은 authenticated입니다.
순번 시퀀스의 PUBLIC·anon·authenticated 권한 회수는 유지합니다.
서버 역할 service_role의 기존 CRUD·순번 사용 권한은 보존했습니다.
이 역할에 기존부터 있던 추가 권한은 이번 테이블 직접 접근 차단 범위에서 변경하지 않았습니다.
자동 RLS 보조 함수의 공개 실행 권한 제거도 유지합니다.
anon과 authenticated 모두 테이블 직접 접근을 거부합니다.
네 RLS 정책은 유지하지만 테이블 권한을 대신 부여하지 않으므로 직접 접근을 열지 않습니다.
DB의 구조와 권한은 supabase/schema.sql에 있으며 메모 본문·실제 키는 포함하지 않습니다.
새 프로젝트에서 이 파일로 구조를 재현할 수 있습니다. 기존 내용을 덮어쓰거나 삭제하지 않습니다.
이 SQL은 기존 메모의 소유자를 자동 변경하지 않습니다.
이미 운영 중인 4단계 DB에는 전체 구조 SQL 대신 supabase/stage5-lockdown.sql을 검토 후 적용합니다.
이 파일은 사용자가 이미 실행한 5단계 권한 회수 SQL과 같습니다. 이번 보완에서는 다시 적용하지 않았습니다.
권한 확인만 하려면 읽기 전용 supabase/verify-stage5.sql을 실행합니다.
테이블 권한뿐 아니라 열 단위 권한의 잔존 여부와 서버 CRUD 권한도 확인합니다.
schema.sql에도 같은 검증을 넣어 열 권한이 남은 채 설정 완료로 처리되지 않게 했습니다.

## API 검사와 DB 정책

4단계의 API 소유자 검사와 RLS 정책을 유지합니다.
service_role은 RLS를 우회하므로 API의 명시적인 소유자 조건이 반드시 필요합니다.
5단계 SQL 적용 전 authenticated는 CRUD 권한이 있었고 anon은 권한이 없었습니다.
적용 후 role_table_grants와 has_table_privilege로 anon·authenticated의
SELECT·INSERT·UPDATE·DELETE·TRUNCATE·REFERENCES·TRIGGER·MAINTAIN이 모두 false임을 확인했습니다.
열 단위 권한도 SQL의 검증 절차에서 남지 않았음을 확인했습니다.
공개 publishable key만 사용하는 실제 원본 GET 및 PATCH 요청 결과는 제출 자기 점검에 기록합니다.
PATCH는 id=is.null 조건으로 기본키가 있는 기존 행을 수정하지 않습니다.
이 점검은 anon 요청이며 실제 authenticated 사용자 토큰의 원본 직접 접근 시험과 구분합니다.
실제 사용자 토큰은 에이전트에게 전달하거나 제출 묶음에 기록하지 않습니다.

현재 파일의 메모 제거만으로 과거 노출이 해소되지는 않습니다.
이전 공개 Git 커밋, 기존 Vercel 배포, 포크·캐시·내려받은 사본은 남을 수 있습니다.
이번 단계는 기존 공개 이력을 삭제하거나 과거 노출을 해결했다고 주장하지 않습니다.

## 실행 및 설정

```sh
npm ci
npm run build -- --local
npm test
npm run check:stage2 -- --deployed
# 커밋과 배포가 일치한 다음 실행
npm run bundle
```

check:stage2라는 명령 이름을 유지하며, 현재 단계의 정적 메모·비밀값 노출과 배포 커밋을 확인합니다.
배포 식별 정보의 step·repoUrl·commit·identityProvider·allowedRoutes·originalApiUrl을 대조합니다.
제출 생성에도 같은 대조를 적용하고, 실제 요청 점검이 하나라도 실패하면 성공한 제출 묶음을 만들지 않습니다.
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
- 5단계 로컬 빌드와 회귀·인증·CRUD·소유자·원본 점검 시험 총 27개: 통과.
- 공식 SDK 로그인·세션 갱신·현재 세션 로그아웃의 서버 전달: 모의 Auth 응답을 사용하는 로컬 시험 통과.
- 정상 서명, 위조 서명, 만료, 잘못된 발급자·대상·역할·사용자 ID, 무토큰 거부 시험: 통과.
- API 시험: 서버 UUID 생성, 지정 UUID, 서버 확인 owner_id, 내 목록, 개별 조회·수정·삭제,
  삭제 후 404, 중복 ID 충돌, 잘못된 입력 거부, A/B 상대 메모 조회·수정·삭제 거부,
  소유자 변경 거부, 헤더·쿼리의 사용자 정보 무시, 심판 소유·소유자 없는 행 기본 거부.
- 실제 DB service_role로 추가·조회·수정·삭제 시험: 통과. 시험 트랜잭션은 롤백했습니다.
- DB 확인: 기존 메모 4건, A 3건·B 1건. 제작 2에서는 DB를 읽기만 했습니다.
- SDK/DOM 모의 화면 시험: 추가·수정·삭제 흐름과 로그아웃 시 화면·작성 내용 제거 통과.
- 제작 3 실제 A 계정 브라우저 CRUD: 사용자 확인 완료. 심판 조건 7개 충족, 최종 90점.
- 4단계 제작 2 배포의 실제 A/B 브라우저 CRUD: 사용자 확인 완료.
- 제작 3 적용 후 DB 재조회: RLS 활성화, 본인 행 정책 4개, 최소 권한 일치, A 3건·B 1건 보존.
- 제작 3 적용 후 anon 직접 Data API 조회: HTTP 401, 42501 권한 거부, 메모 반환 없음.
- 4단계 심판: 조건 6개 충족, 최종 90점(사용자 확인).
- 5단계 권한 회수 후 DB 조회: 두 역할의 직접 권한 없음, 서버 CRUD 유지, RLS와 정책 4개 유지, A 3건·B 1건 보존.
- 5단계 적용 후 실제 A/B 브라우저 CRUD 및 사용자 토큰을 이용한 교차 요청은 아직 미실행입니다.
  앞 단계 사용자 확인과 로컬 시험을 이번 실제 브라우저 검증으로 대신 기록하지 않습니다.
- 5단계 권한 회수 후 A 로그인·시험 메모 추가·수정·삭제: 2026-10-06 사용자 브라우저 확인 완료.
- 검증용 클라우드 브라우저는 인증 서버 연결 오류로 로그인에 실패했습니다. 사용자 브라우저 정상 동작과 구분하며, 이를 배포 장애나 A/B 자동 시험 성공으로 기록하지 않습니다.
- 5단계 적용 후 B 정상 CRUD, 실제 A/B 교차 HTTP 요청, 로그인 토큰을 동반한 원본 API 요청은 아직 미확인입니다.
- 현재 파일 검색: 기존 가상 메모 본문·비밀값 일치 0건. 파일 수는 검사 명령의 출력으로 확인합니다.
- 읽기 전용 DB 확인: stage5_permissions_ok=true, 직접 테이블·열 접근 차단, 서버 CRUD 유지, 메모 4건·정책 4개.
- 수행한 검증과 남은 수동 확인은 docs/STAGE5_VERIFICATION.md에 구분했습니다.
- Supabase 보안 점검: RLS 정책 없음 INFO는 해소됐습니다.
  Auth 유출 비밀번호 검사 비활성화 WARN 1건은 별도 Auth 설정으로 남아 있습니다.
  안내: https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection

## 저장점과 제출

기준 저장점은 「5단계 저장점」이며 가점 보완은 「5단계 공개 가점 조건 반영」에, 마지막 응답 보완은 「5단계 Auth 오류 코드 보존」에 기록했습니다. 배포 커밋을 확인한 뒤 npm run bundle로
현재 커밋의 제출 묶음 artifacts/submission.json을 생성합니다.
제출 주소는 위 Production 주소이며 심판에게 전할 내용은 선택 사항입니다.
자기 점검은 정적 자료, 무토큰 목록·추가·개별 조회·수정·삭제, 잘못된 토큰 조회,
공개 키로 원본 메모 테이블 GET·PATCH 거부, 첫 화면 보안 헤더, 화면 공개 키 제거를 확인하는 11개 점검입니다.
실제 HTTP 상태와 자료 없는 오류 여부만 기록하며 토큰·메모 본문은 묶음에 넣지 않습니다.
만료·위조·다른 대상 토큰의 로컬 시험은 실제 심판 판정으로 기록하지 않습니다.
bundle-notes.json과 artifacts/submission.json은 Git에서 제외합니다.
이전 단계 제출 묶음은 현재 5단계의 증거가 아니므로 최종 저장점에서 새 묶음을 생성합니다.
첫 제출 점수는 80점입니다. 보완 후 점수는 재제출 판정으로 확인합니다. src/decider.mjs와 src/detect.mjs는 보존합니다.
