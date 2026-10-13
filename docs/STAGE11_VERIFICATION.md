# 11단계 접속 앱과 승인

## 범위

10단계는 사용자 심판 결과 100점으로 확인했습니다. 기존 주소·자료·로그인 발급자·소유자·구역·탐지·복구와 XDR를 보존합니다.
기존 docs/DECIDER_REQUEST.md의 18개 항목과 src/decider.mjs 응답 5개 항목은 변경하지 않습니다.
운영 반 엔진의 mTLS 키나 새로운 승인 API 계약은 제공되지 않았습니다. 이를 브라우저 값으로 만들어 채우지 않습니다.
이번 앱은 같은 Vercel/Supabase 안에서 별도의 서버 승인·서명 검증을 구현합니다.
이 접속의 서명 키는 브라우저 WebCrypto가 만든 내보낼 수 없는 ECDSA P-256 CryptoKey로 RAM에만 둡니다.
운영 엔진의 인증서·키를 대신하거나 실제 관리 기기/하드웨어 신뢰를 증명한다는 뜻은 아닙니다.
추가 프로그램 설치·개인키 파일·유료 가입·새 비밀 환경변수를 요구하지 않습니다.

## 사용자 순서

1. 새 화면에서 이메일·비밀번호로 로그인합니다. 로그인 성공만으로 메모를 열지 않습니다.
2. 「이 접속의 기기 승인 요청」을 누릅니다. 요청 → 대기 → 서버 서명 검증 → 승인 상태 재확인을 거칩니다.
3. 서버가 승인한 뒤에만 기존 메모 목록·추가·수정·삭제 화면을 엽니다.
4. 로그아웃하면 서버의 해당 등록을 회수하고 RAM 키와 세션을 지웁니다.
5. 새로고침하거나 다시 열면 다시 로그인·승인합니다. 키/토큰을 브라우저 저장소에 저장하지 않기 때문입니다.
6. Chrome/Edge 메뉴의 앱 설치, iOS/Safari의 홈 화면에 추가를 사용할 수 있습니다.
   설치 표시는 승인이 아니며 앱 설치 이벤트가 메모 화면을 열지 않습니다.

## 서버 승인 정책과 요청 계약

POST /api/auth의 공식 Supabase password 로그인 성공 시에만 3분짜리 등록 허가를 발급합니다.
허가는 서버 HMAC으로 사용자·공개 키 지문·무작위 일회용 번호·만료·프로젝트 주소에 묶습니다.
HMAC 키는 기존 서버 설정에서 도메인을 구분해 사용하며 브라우저·응답·로그로 내보내지 않습니다.
기존 인증 토큰/refresh 토큰만으로 새 등록 허가를 만들 수 없습니다. 비밀번호와 JWT를 직접 만들지 않습니다.
공식 SDK의 persistSession은 false이며 refresh와 로그인 검증은 기존 SDK/verify-login.mjs를 유지합니다.
이전 버전이 남긴 이 앱의 localStorage 세션 한 개만 삭제하고 다른 앱의 저장 자료는 건드리지 않습니다.

| 경로 | 동작 |
|---|---|
| POST /api/device | 검증 로그인 + 서버 등록 허가 + 같은 공개 키 지문을 확인하고 pending 생성 |
| PUT /api/device | 로그인 사용자와 해당 기기의 일회용 challenge 서명을 대조하고 approved로 변경 |
| GET /api/device | 승인된 등록과 현재 서명을 다시 확인해 승인 상태 반환 |
| DELETE /api/device | 검증된 본인 기기 서명으로 해당 등록만 회수 |

허용 경로는 config와 /aleph.json에 위 메서드별 문자열로 선언합니다.
기기 승인 요청 본문의 approved, role, owner_id 같은 값은 받아 신뢰하지 않습니다.
P-256 공개 키만 서버에 저장합니다. 개인키가 들어 있는 JWK는 거부합니다.
보호된 메모·공지·복구 API는 로그인 검사 후 기기 검사를 적용하고 기존 소유자/강사 권한을 다시 검사합니다.

서명 헤더는 X-Vault-Device, X-Vault-At, X-Vault-Nonce, X-Vault-Signature입니다.
JSON 배열로 구분한 버전·검증 사용자·기기·실제 메서드·정확한 경로/쿼리·정렬된 JSON 본문 SHA-256·시각·nonce에 서명합니다.
서명 후 경로/본문/사용자를 바꾸면 거부됩니다. 시각은 60초 이내이며 nonce는 DB에서 한 번만 소비합니다.
무로그인은 401 JSON, 미승인/무서명/위조는 403 JSON이며 보호 자료가 없습니다.
설치 여부나 브라우저의 deviceRegistered/role 헤더로 등록을 대체하지 않습니다.

## 저장소와 오프라인

manifest.webmanifest와 PNG 192/512 아이콘을 제공합니다. 서비스 워커는 공개 오프라인 안내·manifest·아이콘만 준비합니다.
/api 경로와 POST/PUT/DELETE는 인터셉트하거나 캐시하지 않으며 메모·토큰·승인 응답·개인키를 저장하지 않습니다.
오프라인이 되면 화면의 자료와 접속 키도 지우고 연결 후 다시 로그인하도록 안내합니다.
키·등록 허가·access/refresh 토큰은 RAM에서만 쓰며 localStorage/sessionStorage/IndexedDB/CacheStorage에 쓰지 않습니다.

supabase/stage11-device.sql을 학습 프로젝트에 한 번 적용했습니다.
vault_access.devices/request_nonces는 RLS를 켠 비공개 스키마이며 anon/authenticated에 테이블·RPC 접근 권한이 없습니다.
서버 service_role만 등록/승인/조회/회수/nonce 소비 RPC를 수행합니다. 비공개 스키마는 Data API에 노출하지 않습니다. 기존 notes·notices·사본·감사 권한을 풀지 않습니다.
정책 없는 RLS 정보는 이 비공개 테이블의 기본 거부 설계입니다.
[Advisor 안내](https://supabase.com/docs/guides/database/database-linter?lint=0008_rls_enabled_no_policy)
기존 유출 비밀번호 보호 미설정 알림은 이번 변경 범위에서 수정하지 않았습니다.
[기존 Auth 알림](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection)

## 검증과 한계

npm run device:check는 실제 WebCrypto 클라이언트 → 실제 Auth/승인/자료 핸들러 → 가상 DB 어댑터를 실행합니다.
19건에서 승인 전 자료 거부, 승인 후 정상 CRUD, 무서명·경로/본문 변조·다른 사용자·만료·재전송 거부, 로그아웃 회수를 확인했습니다.
실제 학습 DB에서도 pending nonce 거부 → 타인 승인 거부 → 본인 확인 → 정상 nonce 허용 → 재전송 거부를 실행하고 롤백했습니다.
테이블과 RPC의 anon/authenticated 권한이 false이고 서버 권한이 유지됨을 직접 확인했습니다.
키·토큰·메모 본문은 결과로 출력하지 않았습니다. Advisor도 실행했습니다.
기존 인증/소유자/복구 격리 시험은 기기 게이트를 시험용 의존성으로 분리하며 기기 게이트의 실제 검증은 위 새 시험이 맡습니다.
이 격리 시험의 성공을 운영 기기 승인으로 보고하지 않습니다.

브라우저에서 실제 비밀번호 로그인 → 승인 → CRUD 실측과 운영 반 엔진의 mTLS/서명 공격은 아직 미실행입니다.
해당 미실행은 /device-verification.json에도 표시합니다. 실제 승인 버튼 동작은 위 사용자 순서로 다시 확인합니다.
빌드가 가상 검증을 다시 실행해 배포 커밋과 함께 보고서를 만들며 npm run bundle도 최신 배포의 공개 응답을 검증합니다.
이전 규칙 점검은 모두 실행하고 결과를 묶어 제출 최대 20개 형식을 유지합니다.

전체 회귀 시험: main 130건, defense-r5 115건 모두 통과했습니다.
