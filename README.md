# BYTE BACK 방어전 자료실 R5

## 2단계 점수 보완용 저장점

이 브랜치 `score-stage2`는 기존 2단계 저장점 `c0f9c3b`에서 분리했습니다.
학생이 확인한 기존 2단계 점수는 90점이며, 재제출 결과는 심판이 판정합니다.
5단계 작업을 이어가는 브랜치는 `defense-r5`입니다.

- 저장소: https://github.com/rlatmdgus4141/choi-bujang-secret-vault
- 2단계 제출 주소: https://choi-bujang-secret-vault-stage2-rlatmdgus4141.vercel.app
- 5단계 주소: https://choi-bujang-secret-vault-rosy.vercel.app

## 현재 기능과 한계

가상 메모 네 건은 학습 DB의 `public.notes`에 있습니다.
첫 화면은 `GET /api/notes` 서버 함수에서 받은 자료를 카드로 표시합니다.
서버 함수만 `SUPABASE_URL`과 서버 전용 `SUPABASE_SECRET_KEY`를 읽습니다.
브라우저 파일·Git·응답·로그·제출 묶음에는 서버 키를 넣지 않습니다.
화면은 메모 내용을 `textContent`로 표시합니다.

2단계 API는 의도적으로 비로그인 읽기를 허용합니다. 가상 자료만 사용합니다.
이 주소는 2단계 재현용이며 실제 개인정보와 실제 학생 자료를 넣으면 안 됩니다.
로그인·소유자 검사와 메모 추가·수정·삭제는 5단계 주소에서 유지합니다.
이 브랜치로 DB의 소유자·권한·정책·메모를 변경하지 않습니다.

현재 공유 학습 DB는 5단계까지 적용된 상태입니다. RLS는 켜져 있으며,
`PUBLIC`, `anon`, `authenticated`의 메모 테이블 직접 권한은 회수되어 있습니다.
서버 역할은 기존 권한으로 자료를 읽습니다. 이 브랜치의 과거 스키마 SQL은
2단계 설명 자료이므로 현재 공유 DB에 다시 실행하지 않습니다.

## 공개된 100점 가점 조건

1. `/data.json`에는 `{"notes":[]}`만 있고 메모와 1단계 표시가 없습니다.
2. 빌드는 Vercel 시스템 환경변수로 `/aleph.json`을 자동 생성합니다.
   실제 저장소·커밋·단계를 기록하며 빌드 과정에서 삭제하지 않습니다.
3. `vercel.json`은 첫 화면을 포함한 응답에
   `X-Content-Type-Options: nosniff`를 설정합니다.

이 조건은 배포 후 실제 비로그인 HTTP 응답으로 확인합니다.
설정 파일이나 로컬 테스트만으로 심판의 100점 판정을 주장하지 않습니다.

## 다시 실행하고 확인하기

```sh
npm ci
npm run build -- --local
npm test
npm run check:stage2
```

로컬 빌드는 정적 파일을 확인하며 서버 실행이나 실제 배포를 증명하지 않습니다.
환경변수는 기존 Vercel 프로젝트의 Production 설정을 사용합니다.
키는 공식 비밀 입력란에만 넣으며 채팅으로 요구하거나 출력하지 않습니다.

배포 후 현재 커밋과 실제 HTTP 응답을 확인합니다.

```sh
npm run check:stage2 -- --deployed
npm run bundle
```

시크릿 창에서 위의 2단계 주소를 열면 가상 메모 카드 네 건이 보여야 합니다.
`/data.json`은 메모 0건, `/aleph.json`은 현재 단계 2와 커밋이 보여야 합니다.
첫 화면의 응답 헤더는 개발자 도구 Network에서 확인합니다.
`GET /api/notes`는 2단계의 남은 약점으로 비로그인 자료 조회를 허용합니다.
GET 이외의 요청은 405, 서버 설정 누락은 503, DB 연결 실패는 상세 없는 502입니다.

`npm run check:stage2`는 이전 공개 커밋의 가상 메모 문장을 메모리로만 읽고,
현재 소스·정적 배포 파일에서 검색합니다. 본문·키는 출력하지 않습니다.
`src/attack-check.mjs`는 실제 정적 자료와 공개 서버 API 요청 결과만 기록합니다.
자기 점검과 심판 판정은 구분합니다. `bundle-notes.json`과
`artifacts/submission.json`은 Git에 넣지 않습니다.

## 과거 노출의 한계

현재 정적 파일과 이 브랜치에는 가상 메모 본문이 없습니다.
이전 공개 커밋, 이전 배포, 포크·캐시·내려받은 사본은 그대로 남을 수 있습니다.
현재 파일 삭제로 과거 노출이 해소됐다고 주장하지 않습니다.
2단계 재현 주소의 서버 API도 의도적으로 공개되어 있다는 한계를 유지합니다.
실제 비밀값·개인정보는 이 실습에 사용하지 않습니다.

공통 작업 규칙과 저장점 규칙은 [AGENTS.md](AGENTS.md)를 따릅니다.
