# BYTE BACK 방어전 자료실 R5

## 현재 단계: 2단계 · 자료를 코드 밖으로 옮깁니다

1단계는 r5-rc1의 커밋 0f9a3c9에서 시작했고 학생이 포털에서 100점을 확인했습니다.
같은 저장소의 defense-r5 브랜치에서 이어갑니다.

- GitHub: https://github.com/rlatmdgus4141/choi-bujang-secret-vault
- Production: https://choi-bujang-secret-vault-rosy.vercel.app
- 학습용 Supabase 프로젝트: choi-bujang-secret-vault

가상 메모 네 건은 Supabase public.notes로 이전했습니다.
owner_id uuid는 다음 단계용이며 auth.users 외래키는 없습니다.
RLS를 켜고 PUBLIC, anon, authenticated의 테이블 권한을 제거했습니다.
서버 역할 service_role에는 읽기 권한만 명시적으로 부여했습니다.
자동 RLS 보조 함수의 공개 실행 권한도 제거하고 이벤트 트리거는 유지합니다.
RLS 정책이 없는 것은 브라우저 역할의 직접 접근을 전부 거부하기 위한 의도입니다.

## 화면과 서버

public/index.html은 GET /api/notes를 통해 자료를 불러옵니다.
api/notes.js는 Vercel 서버 함수이며 환경변수 SUPABASE_URL, SUPABASE_SECRET_KEY를 읽습니다.
서버 전용 Secret API Key는 공식 설정 화면에서 Production 환경변수에 직접 입력합니다.
키를 채팅, 코드, Git, 브라우저 파일, 응답, 로그, 제출 묶음에 넣지 않습니다.
NEXT_PUBLIC_ 접두사는 사용하지 않습니다.

API는 아직 공개 주소이며 비로그인 방문자도 가상 메모 네 건을 읽을 수 있습니다.
RLS는 서버 키가 사용하는 역할의 접근을 막지 않습니다.
로그인·소유자 확인은 3단계에서 구현하므로 실제 개인정보와 실제 학생 자료는 넣지 않습니다.
API는 필요한 자료 필드만 반환하고 DB 오류 상세와 환경변수는 반환·기록하지 않습니다.
캐시는 no-store이며 GET 이외 요청은 HTTP 405로 거부합니다.
키 누락·잘못된 키 유형은 HTTP 503, DB 연결 실패는 상세 없는 HTTP 502로 응답합니다.

루트와 public/data.json에는 빈 notes 배열만 남기며 1단계 확인 표시도 제거합니다.
빌드는 2단계에서 메모·확인 표시·추가 필드가 들어간 data.json을 거부해 재노출을 방지합니다.
public/aleph.json은 Vercel의 실제 저장소·커밋·배포 주소와 현재 단계를 기록합니다.
judgeIssuer는 시작 틀의 운영 설정을 유지합니다.

## SQL 보관과 실행

메모 본문이 포함된 aleph_stage2_setup.sql은 Git 밖에서 따로 제공합니다.
Supabase 연결 기능으로 이미 실행했으므로 SQL Editor에서 다시 실행할 필요는 없습니다.
재실행이 필요하면 공식 SQL Editor에서 해당 파일을 실행합니다.
위치가 같은 기존 행은 덮어쓰지 않습니다. 공개 저장소나 public에 SQL을 복사하지 않습니다.
확인 결과: 메모 4건, owner_id uuid, RLS 활성화, 익명·로그인 역할 SELECT 불가,
서버 역할 SELECT 가능, 외래키 0개.

## 다시 실행하고 확인하기

```sh
npm ci
npm run build -- --local
npm run test:r5
npm run test:stage2
npm run check:stage2
```

로컬 빌드는 정적 파일만 생성하며 API 실행이나 Vercel 배포를 증명하지 않습니다.
실제 배포는 Vercel Production 브랜치 defense-r5를 사용합니다.
서버 키가 없으면 자료 화면에 오류가 나므로 키 설정 후 배포해야 합니다.

배포 후 실행:

```sh
npm run check:stage2 -- --deployed
npm run bundle
```

첫 명령은 이전 공개 커밋에서 가상 메모 검색 문장을 메모리로 읽어,
현재 작업 파일과 비로그인 배포의 /, /data.json, /aleph.json, 연결된 정적 JS/JSON에서 검색합니다.
메모 본문·키는 출력하지 않고 일치 건수와 경로만 기록합니다.
/aleph.json의 저장소·단계·커밋도 현재 HEAD와 대조합니다.
현재 GitHub 파일은 git fetch origin defense-r5 뒤 원격 커밋이 HEAD와 같은지 확인합니다.
정적 빌드 산출물은 비공개 패턴 파일을 사용해 rg로 같은 문장을 검색할 수 있습니다.

시크릿 창에서 /에 카드 네 건이 보이고 /data.json의 notes가 비어 있어야 합니다.
/api/notes는 아직 비로그인 HTTP 200으로 가상 자료를 반환하는 남은 약점입니다.
DB에 직접 접근하는 anon·authenticated 역할은 자료 읽기가 거부되어야 합니다.
src/attack-check.mjs는 빈 정적 자료와 공개 API의 남은 약점을 실제 요청으로 각각 기록합니다.
메모 본문은 제출 묶음에 넣지 않습니다. 학생의 자기 점검은 심판 판정이 아닙니다.

## 검증 기록

- Supabase DB 이전과 권한 확인: 실행 완료.
- 자동 RLS 보조 함수의 공개 실행 권한 제거 후 보안 점검: WARN 없음.
- 로컬 빌드: 통과. 기존 테스트 2개와 2단계 테스트 5개: 모두 통과.
- 현재 작업 파일 26개 검색: 메모 본문·비밀값 일치 0건.
- SUPABASE_URL과 서버 키: Production 등록 확인.
- GitHub 최신 커밋과 Production은 아래 검증 명령으로 대조합니다.
- 실제 정적 자료·공개 API 요청 결과는 제출 묶음의 attackAttempts에 기록합니다.
- 심판이 S02_MARKER_IN_STATIC을 보고해 정적 data.json의 1단계 표시를 제거했습니다.
  자기 점검에도 표시 제거 조건과 재발 방지 시험을 추가했습니다. API와 DB는 유지합니다.

## 과거 노출의 한계

이번 단계는 현재 파일과 새 배포에서 메모 시드를 제거합니다.
이전 공개 Git 커밋, 기존 Vercel 배포, 포크·캐시·내려받은 사본은 그대로 남을 수 있습니다.
현재 파일 삭제만으로 과거 노출이 해소됐다고 주장하지 않습니다.
이번 실습에는 가상 자료만 사용하며 실제 비밀값의 과거 노출은 별도 폐기·교체가 필요합니다.

## 저장점과 제출

검증 후 변경 파일과 비밀값 검색 결과를 확인하고 2단계 저장점으로 커밋합니다.
aleph.config.json의 단계·저장소·배포 주소는 구현과 맞췄습니다.
bundle-notes.json에 단계 설명을 작성하고 npm run bundle을 실행합니다.
bundle-notes.json, artifacts/submission.json, 서버 키, 메모 SQL은 커밋하지 않습니다.
로그인·허용 경로·원본 API·정책 변경은 해당 후속 단계에서만 추가합니다.
src/decider.mjs, src/detect.mjs의 시험은 반 엔진 또는 운영 심판의 결과가 아닙니다.
자세한 공통 규칙은 [AGENTS.md](AGENTS.md)를 따릅니다.
