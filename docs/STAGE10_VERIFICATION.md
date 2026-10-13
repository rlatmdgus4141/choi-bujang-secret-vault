# 10단계 복구와 검증

## 사본의 범위와 신뢰

사용자가 100점 통과를 확인한 9단계 main 커밋 f2c660fb2241343fe2db71123d4981d6a34c10ad의
`src/decider.mjs`를 정책 사본으로 기록했습니다. 사본의 소스 SHA-256을 도구 내부에 고정해 대조합니다.
사본이 없거나 달라지면 중단합니다. 정책 복구 대상은 `recovery/test-decider.mjs` 한 파일입니다.
`src/decider.mjs`, 다른 서비스 정책과 기존 감사 기록은 복구 도구가 쓰지 않습니다.
사본과 시험 정책이 같은 현재 상태에서는 변경 0건입니다. 시험에서만 기기 규칙을 바꿨다가 복원했습니다.

실행 전에 `npm run recovery:policy:preview`로 버전·커밋·변경 줄·대상을 확인합니다.
출력의 confirmation 값을 확인한 뒤 `npm run recovery:policy:restore -- --confirm <confirmation>`을 실행합니다.
확인 이후 시험 정책이 바뀌면 기존 확인 번호를 거부합니다. 전용 잠금으로 도구 간 동시 복원을 막습니다.
복원 감사는 `recovery/policy-audit.log`에 추가하며 기존 행을 지우지 않습니다. 로그는 Git에서 제외합니다.

## 비공개 메모 사본과 POST 경로

서비스: 기존 Vercel 자료실과 같은 Supabase 프로젝트.
경로: `POST /api/restore`, aleph.config.json의 restoreRoute는 `/api/restore`입니다.
allowedRoutes에 `POST /api/restore`를 함께 선언하고 빌드의 `/aleph.json`에도 게시합니다.
Authorization은 기존 verify-login.mjs로 검증합니다. 본문은 `{ "id": "<UUID>" }`입니다.
선택적으로 `{ "id": "<UUID>", "dryRun": true }`를 보내면 사본을 검증하고 변경 없이 범위·해시를 확인합니다.
소유자·role·메모 내용은 본문에서 받지 않습니다. 검증된 사용자 ID로만 해당 사본을 선택합니다.
응답은 `{id,restored,hash,backupVersion}`이며 메모 내용, 키, 토큰을 돌려주거나 로그에 적지 않습니다.
무로그인은 401 JSON, 없는/타인 사본은 404, 손상 사본은 409, 연결 장애는 502입니다.

`supabase/stage10-recovery.sql`은 최초 한 번 적용하는 비파괴 초기화입니다. 이미 적용한 DB에 재실행하지 않습니다.
`vault_recovery.note_backups`와 `vault_recovery.audit`는 공개 API에 노출하지 않는 별도 스키마입니다.
RLS를 켜고 PUBLIC·anon·authenticated의 스키마/테이블/함수 권한을 회수했습니다.
service_role은 사본 SELECT, 감사 SELECT/INSERT만 가능합니다. 사본 UPDATE/DELETE나 감사 DELETE를 주지 않습니다.
메모 생성 INSERT 트리거만 권한을 한정한 SECURITY DEFINER로 최초 사본을 작성합니다.
검색 경로는 빈 값으로 고정했고 트리거 함수의 직접 실행 권한은 모두 회수했습니다.
기존 네 가상 메모의 사본을 만들었고 새 시험 메모도 생성과 동시에 사본을 기록합니다.
UPDATE·DELETE가 사본을 덮어쓰지 않습니다. 정당한 수정의 새 백업 버전 생성은 이번 단계 범위 밖입니다.
사본에는 notes/auth.users 외래키를 두지 않아 원본 삭제와 임시 심판 계정에 영향을 받지 않습니다.

복구 RPC는 SECURITY INVOKER이며 service_role만 실행 가능합니다.
ID와 검증된 소유자를 대조하고, 사본의 UTF-8 길이 접두 제목/본문 SHA-256과 버전을 검증합니다.
트랜잭션 잠금 후 대상 한 행만 upsert하고 원래 ID·소유자·순번·생성 시각·내용 해시를 대조합니다.
타인 행이나 순번 충돌, 검증 실패는 전체 트랜잭션을 취소합니다. 다른 행을 지워 충돌을 해결하지 않습니다.
감사에는 ID·소유자·해시·행동만 추가합니다. 기존 메모/공지 권한과 API의 로그인·소유자 검사는 유지합니다.

## 실행 근거

Supabase 학습 DB에서 B의 메모 한 건을 대상으로 변조 → 복구, 삭제 → 복구를 실행했습니다.
미리보기 검증, ID/소유자/해시 일치, 타인 소유자 거부, 다른 메모 보존, 기존 감사 보존이 모두 true였습니다.
B의 임시 가상 메모 생성 → 사본 기록 → 삭제 → 복구도 true였습니다.
사본의 내용을 손상시킨 별도 시험은 복구 거부와 메모 무변경이 모두 true였습니다.
두 시험은 BEGIN/ROLLBACK 안에서 실행해 시험 전 메모와 감사 기록을 그대로 유지했습니다.
실제 DB 복구 함수의 시험이며, 브라우저 B 토큰으로 배포 HTTP 복구를 실행한 결과는 아닙니다.

`npm run test:recovery` 7건은 사본 누락/손상/확인 번호 만료, 다른 정책·감사 보존,
정상/미등록/전체 목록 판정, 복구 API 인증·소유자·응답 검증·경로 제한을 시험합니다.
기존 A/B CRUD 및 타인 행 거부 시험을 포함한 `npm test`와 `npm run decider:test`,
`npm run fixture:7`, `npm run detect:test`를 다시 실행합니다.
실행 결과: main 전체 123건, defense-r5 배포 브랜치 전체 108건 모두 통과했습니다.
기기 연습 4건, fixture:7 정상/복합 이상, detect:test 12건도 통과했습니다.
판정기 규칙과 로그인 검증 도우미는 9단계 파일과 동일합니다.

## 복구 후 1~9단계 재시험 순서

| 단계 | 정상 확인 | 금지 확인 | 실행 범위 |
|---|---|---|---|
| 1~2 | 첫 화면·aleph.json HTTP 200 | data.json 메모 0건, 현재 정적 시드 없음 | 로컬 빌드 및 배포 bundle |
| 3 | A 로그인·본인 CRUD | 무로그인·위조·만료·다른 발급자 토큰 거부 JSON | 서명된 모의 API; 무로그인은 배포 bundle |
| 4 | A/B 각각 자기 CRUD | 상대 행 GET/PUT/DELETE와 소유자 변경 거부 | 서명된 모의 API; DB 권한 실측 |
| 5 | 서버 service_role CRUD 유지 | anon/authenticated 원본 직접 권한 없음 | DB 권한 실측; anon GET/PATCH는 배포 bundle |
| 6 | 등록 기기 allow | 미등록/정보 누락 deny | decider:test·기기 모의 시험 |
| 7 | 정상 allow, 새 추가 확인 뒤 allow | 복합 이상은 step_up | fixture:7·모의 시험; 실제 재로그인은 미실행 |
| 8 | 본인 한 건 경로 허용 | 전체 목록·공지 쓰기·타인 행 거부 | 판정기와 서명된 모의 API |
| 9 | 정상 사건 observe | 복합 기기 사건만 회수 제안 | detect:test; 운영 회수/시간은 심판 확인 |

B 브라우저에서 자신의 시험 메모를 확인한 뒤 POST 복구를 실행하고 같은 ID를 GET해 대조합니다.
A 정상 CRUD와 B의 A 메모 거부를 다시 확인합니다. 실사용자 토큰은 문서/콘솔 출력/Git에 넣지 않습니다.
브라우저의 실제 로그인/CRUD 재확인과 운영 심판의 1~9 대표 공격은 미실행이며 심판 재판정으로 확인합니다.
`npm run bundle`은 배포 커밋 대조와 공개 응답·가상 사건 점검을 합쳐 최대 20개 결과를 생성합니다.
여기에 복구 POST의 401 거부를 기존 무로그인 메모 추가 점검과 함께 검증하며 성공 응답을 꾸미지 않습니다.

## DB 점검 정보

보안/성능 Advisor도 실행했습니다. 비공개 사본/감사의 RLS에 정책이 없는 것은 기본 거부 설계입니다.
[안내](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy)
기존 Auth 유출 비밀번호 보호 미설정 알림과 기존 인덱스 미사용 정보가 있었고 이번 복구 변경에는 포함하지 않았습니다.
[Auth 알림 안내](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection)

## 심판 실패 두 항목의 보완

기존 묶음에는 사본 검증/복원 후 재시험의 별도 결과가 없었고 구역 점검의 내부 성공으로만 합쳐졌습니다.
그 연결 누락을 유력한 원인으로 보고 전용 실행 명령과 공개 근거를 추가했습니다. 내부 심판 판단식은 확인되지 않았습니다.

`npm run recovery:check -- --write`는 다음 순서대로 실제로 실행하며 실패하면 결과를 성공으로 저장하지 않습니다.

1. 디스크에서 정책 사본을 재읽고 고정 SHA-256·정확한 검증 커밋·버전을 비교합니다.
2. 임시 시험 정책의 기기 규칙을 바꾸고 복원할 버전과 변경 줄을 미리 봅니다.
3. 사본 손상/누락을 각각 넣어 복원이 거부되고 시험 정책·기존 감사가 그대로인지 확인합니다.
4. 사본을 다시 읽어 검증한 뒤 미리 본 확인 번호로 시험 정책만 복원합니다. 임시 출력과 복원 파일도 다시 읽어 해시를 대조합니다.
5. 복원한 파일을 로드한 뒤 정상 등록 기기 허용·미등록 거부·복합 이상 추가 확인·새 추가 확인 허용·전체 목록/공지 쓰기 거부를 재실행합니다.
6. 탐지 12건과 서명 키를 RAM에서만 사용하는 가상 A/B API 요청을 재실행합니다. 자기 CRUD·타인 접근·소유자 변경·무로그인·위조/만료/다른 서비스 토큰·공지 쓰기를 확인합니다.
7. 가상 메모 B의 검증 사본을 복구한 이후 API 정상/거부 요청을 실행하며, 비공개 실제 DB에서 실행한 시험과 구분합니다.

결과는 사본 검증 6건, 복원 후 재시험 39건 모두 통과했습니다. 각 항목의 실제·기대 값과 소스 해시를
`recovery/verification.json`에 기록하고 빌드 때 다시 실행한 보고서를 `/recovery-verification.json`에 제공합니다.
URL은 `https://choi-bujang-secret-vault-rosy.vercel.app/recovery-verification.json`입니다.
`scope=local_synthetic_only`, `productionPolicyChanged=false`, 실제 미실행 항목을 그대로 표시합니다.
실제 사용자 이메일·메모 본문·JWT·개인키·서버 키는 보고서에 없습니다.

제출 자기 점검에도 `backup_verified`, `post_restore_retest`를 별도 항목으로 생성합니다.
기존 기기 등록 3건은 시험을 생략하지 않고 결과만 한 묶음으로 합쳐 최대 20개 계약을 유지합니다.
실제 복구 API나 DB 사본의 권한은 이번 근거 보완으로 변경하지 않았습니다.

이번 보완 후 전체 회귀 시험: main 124건, defense-r5 109건 모두 통과했습니다.
