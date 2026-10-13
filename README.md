# 7단계 저장점 · 보너스 모듈 보존

## 8단계 두 번째 보완 · 연습 자원의 주체 제한

/notes/demo 읽기 예외에서 주체를 구분하지 않은 결함을 재현하고 수정했습니다.
공식 연습 자료의 반·프로젝트·사용자·기기·정확한 읽기 경로만 명시적 권한으로 등록합니다.
다른 주체/기기/범위는 추가 인증·본문 역할·헤더와 관계없이 거부합니다.
가상 연습 권한을 실계정 소유권으로 추정하지 않으며 실제 API의 소유자 검사는 defense-r5에서 유지합니다.
확인: 판정기 회귀 13개와 공식 decider:test. 실제 심판 재제출 성공은 아직 미확인입니다.


## 8단계 첫 제출 오류 보완

심판 S08_OTHER_ZONE_ALLOWED에 대해 판정기의 자원 ID 허용 범위를 최소 수정했습니다.
임의 영숫자 문자열 대신 실제 API와 같은 UUID 경로를 사용합니다.
공식 /notes/demo 가상 연습은 GET만 유지하고, 다른 임의 자원과 공지 수정은 거부합니다.
원본 API의 소유자·강사 검사 및 기기·추가 확인 규칙은 보존합니다.
이는 경로 과잉 허용 후보를 수정한 것이며 실제 심판 재제출 성공은 아직 확인하지 않았습니다.
실행: `node --test test/stage6-decider.test.mjs test/stage7-decider.test.mjs test/stage8-decider.test.mjs`.


## 8단계 저장점 · 판정기 자원 구역

7단계는 사용자 제출 결과 90점으로 통과했습니다.
현재 「8단계 저장점」에는 Production defense-r5와 동일한 resource_zones 판정기와 회귀 시험을 반영했습니다.
기존 XDR01/02와 main 시작 틀 화면은 보존합니다. 실제 메모·공지 API와 step 8 배포 설정은 defense-r5에 있습니다.
정확한 notes/notices 서비스·경로·메서드를 구별하고, 미등록 기기 및 복합 이상 접속 규칙은 유지합니다.
계약에는 소유자/강사 역할이 없으므로 최종 Production API에서 저장된 소유자·강사 권한을 확인합니다.
엔진의 공지 변경은 역할 계약이 없어 기본 거부합니다. 실제 엔진 강사 수정은 미실행입니다.
상세 범위: [docs/STAGE8_VERIFICATION.md](docs/STAGE8_VERIFICATION.md).
확인: `node --test test/stage6-decider.test.mjs test/stage7-decider.test.mjs test/stage8-decider.test.mjs` 및 `npm run decider:test`.
공식 가상 시험과 로컬 시험은 실제 심판 판정이 아닙니다.


## 7단계 저장점 · 복합 이상 접속의 추가 확인

6단계는 사용자 재제출 결과 90점으로 통과했습니다(2026-10-13).
7단계에는 기존 device_registered와 기본 거부 규칙을 유지하고 step_up_required를 추가했습니다.
현재 동작: 정상 notes 읽기 allow, 미등록 deny/device_not_registered, 복합 이상 step_up/step_up_required입니다.
등록 상태나 접속 정보는 브라우저가 아니라 반 엔진이 검증해 전달한 계약 필드만 읽습니다.

### 출처와 입력 검사

- `signals.source === 'judge_fixture'`: 엔진이 전달하는 가상 사건으로만 다룹니다. 실제 사용자 위치라는 뜻이 아닙니다.
- `signals.source === 'none'`: region/network의 unknown을 그대로 유지합니다. local/usual로 채우지 않습니다.
- 출처 불명, 누락 필드, 잘못된 시각·사건 형식은 기존 기본 거부를 사용합니다.
- 클라이언트 위치·시각·재로그인 헤더와 임의 identity/geo 필드는 읽지 않습니다.
- recentEvents는 최대 12개이며 kind·ageSeconds·count 형식을 검사합니다.

### 가상 사건 정책과 사유

foreign 지역, 00~05시, unusual 네트워크, 최근 300초 risk_signal 합계 10건 이상 중
두 가지 이상이 겹치면 추가 확인을 요구합니다. 수치는 이 실습의 명시적인 정책이며 실제 개인의 생활 패턴을 추정한 값이 아닙니다.
지역 하나 또는 시각 하나만으로 차단하지 않습니다. 추가 확인 응답에는 자료 없이
reasonCode와 ruleIds의 step_up_required만 반환하며 원문 사건·토큰을 로그에 넣지 않습니다.
미등록 기기는 재확인 여부와 무관하게 6단계 규칙에서 먼저 거부합니다.

### 재로그인 계약과 실측 범위

docs/DECIDER_REQUEST.md에는 엔진의 stepUp `{verified, authAgeSeconds}`가 있습니다.
엔진이 같은 신원을 새 로그인으로 검증해 준 요청에서 verified가 정확히 true이고 나이가 0~900초일 때만
추가 확인 조건을 해소합니다. 이후에도 기존 서비스·동작·경로 허용 조건을 다시 검사합니다.
문자열 true, 누락·null·음수·901초 이상 시각은 확인 완료로 취급하지 않습니다.
판정기가 토큰을 만들거나 토큰 원문에서 재로그인을 추정하지 않습니다.

저장소에는 제공 엔진의 실제 재로그인 도전·완료를 호출할 경로와 실행 세션이 없습니다.
따라서 이번 검증은 공식 가상 사건의 확인 전/후 판정이며, 실제 동일 사용자 재로그인 시각 검증,
실제 민감 자료 차단 및 새 로그인 뒤 허용 실측은 **미실행**입니다. 엔진이 준비된 환경에서 심판이 확인합니다.
기존 Vercel 화면에 임의의 재인증 확인 기능이나 자체 발급 토큰을 추가하지 않았습니다.

### 확인 명령과 결과

```sh
npm run decider:test
npm run fixture:7
node --test test/stage6-decider.test.mjs test/stage7-decider.test.mjs
# defense-r5의 현재 커밋 배포가 완료된 뒤
npm run bundle
```

공식 연습 네 항목(등록 정상, 미등록, 복합 이상, 다시 확인한 복합 이상)이 모두 통과했습니다.
fixture:7은 정상 allow / 복합 이상 step_up입니다. 배포 브랜치 회귀 시험 44개가 통과했고,
main의 기기·추가 확인 시험 9개와 보너스 회귀 시험 20개가 통과했습니다.
이 결과는 심판 점수가 아닙니다. 다음 기록은 이전 단계의 저장점입니다.

배포 설정은 step 7이며 기존 주소·발급자·허용 API 경로·원본 API·judgeIssuer를 유지합니다.
심판 기본 브랜치 main과 배포 브랜치 defense-r5에 같은 판정기를 반영합니다.
main의 보너스와 시작 틀은 보존하고 앱 배포는 defense-r5만 사용합니다.


## 6단계 저장점 · 등록 기기 읽기 조건

`src/decider.mjs`에 `device_registered` 규칙을 구현했습니다.
사용자는 엔진이 검증한 `subjectId`, 기기는 `deviceId`, 등록 여부는 `deviceRegistered`로 전달됩니다.
`deviceRegistered === true`일 때만 엔진이 확인한 사용자·기기의 notes GET 읽기 경로를 허용합니다.
미등록·누락·잘못된 등록 값은 deny / device_not_registered입니다.
다른 서비스·동작·일치하지 않는 경로는 기존 기본 거부를 유지합니다.
브라우저가 보낸 userId·role·등록 여부를 새 신뢰 값으로 사용하지 않습니다.
인증서·CA·개인키·새 접속 프로그램은 만들지 않았습니다.

```sh
npm run decider:test
node --test test/stage6-decider.test.mjs
# 배포 브랜치 defense-r5의 커밋과 실제 배포가 일치한 뒤 실행
npm run bundle
```

공식 로컬 연습 결과: 등록 기기 정상 요청 allow, 미등록 가상 요청 deny / device_not_registered 모두 통과했습니다.
6단계 경계값 시험 3개도 통과했습니다. 배포 브랜치 전체 회귀 시험 38개와 main의 보너스 회귀 시험 20개가 통과했습니다.
추가 시험은 등록 여부 누락·문자열·숫자 등도 거부하고 notes 읽기 외 동작을 열지 않는지 확인합니다.
이 시험은 가상 요청의 정책 검사이며 실제 인증서·mTLS·사용자-기기 결합 공격은 심판이 검사합니다.
기존 자료실 주소와 로그인·메모 CRUD 화면, 서버 API와 DB 설정은 유지합니다.
실제 사용자 브라우저의 정상 화면은 배포 후 다시 확인하고, 미실행 시험을 완료로 기록하지 않습니다.

배포 브랜치는 defense-r5이고 기본 브랜치 main에도 동일한 src/decider.mjs를 반영합니다.
배포 브랜치 설정은 step 6이며 기존 로그인 발급자·허용 API 경로·원본 API 주소·judgeIssuer를 유지합니다.
main의 시작 틀 설정은 보존하고, 심판이 읽는 기기 판정 규칙과 시험만 같은 버전으로 맞춥니다.
main에 남아 있는 시작 틀 화면을 새로 운영 배포하지 않습니다.
보너스 모듈은 기존 판정기에 덧붙이는 연결이며 이번 기기 규칙도 그대로 전달합니다.
이후 문서의 starter.deny 전용 설명은 6단계 이전 기록입니다.


기본 브랜치 `main`에서 심판이 읽는 `xdr/brute-force/decide.mjs`를 제공합니다.
이 모듈은 `defense-r5`의 `3b89300878a128e99c520591daa6b0b9f7ecc667`과 같습니다.
이전 판정은 시작 틀 커밋 `8a0927400ec0`을 읽어 모듈을 찾지 못했습니다.

## 현재 보너스 상태

- xdr-01 무차별 로그인: 사용자에게 심판 통과 확인을 받았습니다.
- xdr-02 웹 주입: `xdr/web-injection/decide.mjs` 구현과 로컬 검증을 완료했고 심판 제출을 기다립니다.
- 웹 주입 공식 경보 26건: block 8 · alert 9 · record 9. 정상 이벤트 9건의 추가 차단은 0건입니다.
- SQL·스크립트·경로 이탈·명령 주입의 명확한 반복 시도만 차단 후보로 삼고, 단발성 의심 경보는 알립니다.

```sh
npm run xdr:run -- web-injection
npm run xdr:web:read
npm run xdr:web:respond -- web-injection
npm run test:xdr
```

`decide.mjs`는 import 없이 단독 실행되며 로그·만료 규칙 처리는 `respond.mjs`에 분리했습니다.
현재 `src/decider.mjs`의 `starter.deny`는 그대로입니다. 정상 통과는 별도 시험용 기본 정책에서 검증했습니다.
운영 Wazuh나 반 엔진이 연결됐다고 주장하지 않습니다. 상세 근거와 제한은 [웹 주입 문서](docs/XDR_WEB_INJECTION.md)를 참고하세요.

## 브랜치와 배포

- `main`: 기존 시작 틀을 보존하고 보너스 모듈·시험·문서를 추가한 제출 브랜치입니다.
- `defense-r5`: 1~5단계 총 500점을 받은 자료실과 실제 운영 배포의 브랜치입니다.
- 제출 배포 주소: https://choi-bujang-secret-vault-rosy.vercel.app
- 제출 저장소 주소: https://github.com/rlatmdgus4141/choi-bujang-secret-vault

`main`의 시작 틀 설정·정적 가상 자료는 운영 자료실을 나타내지 않습니다.
보너스 심판의 기본 브랜치 파일 조회를 고치기 위해 앱 설정이나 기존 판정기 규칙을 변경하지 않았습니다.

## 실행과 확인

```sh
npm run xdr:run -- brute-force
npm run test:xdr
npm run xdr:respond -- brute-force
```

공식 가상 경보 28건의 결과는 block 10 · alert 9 · record 9입니다.
독립된 시험용 기본 정책에서 정상 이벤트 9건의 추가 차단은 0건입니다.
판단 파일은 다른 파일·패키지를 불러오지 않고 격리 환경에서 단독 실행됩니다.
근거·만료 규칙·운영 연결의 한계는 [XDR 문서](docs/XDR_BRUTE_FORCE.md)에 있습니다.
실제 Wazuh/반 엔진 연결이나 심판 통과를 로컬 시험 결과로 주장하지 않습니다.

---

## 아래는 보존한 시작 틀 안내입니다

# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
