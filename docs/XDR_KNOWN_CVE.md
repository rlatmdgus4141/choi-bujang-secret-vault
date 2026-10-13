# XDR 3 · 알려진 취약점 악용 탐지

## 범위와 근거

CVE-2021-44228의 공격자 제어 JNDI 원격 엔드포인트 형태를 요청 인자와 머리글에서 찾습니다.
정규화는 URL 인코딩과 제한된 문자 조합의 문자열 변환만 수행합니다. 조회 구문을 실행하거나 목적지에 연결하지 않습니다.
원격 조회 구문이 완전하고 출발 주소가 유효하면 한 건도 차단 후보입니다.
DNS형 점검·잘린 구문·전용 점검 도구 이름·T1190 의심 경보만으로 자동 차단하지 않습니다.
일반 CVE 검색, jndi 수업 단어, 정상 브라우저 이름에는 악용을 확정하는 근거가 없습니다.
CVE/T1190은 공격 형태의 근거이며 0.85/0.5 기준과 15분 차단은 이 과제의 정책입니다.

- Apache: https://logging.apache.org/security.html#cve-2021-44228
- NIST NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- MITRE T1190: https://attack.mitre.org/techniques/T1190/
- 전용 점검 도구의 공식 설명: https://github.com/fullhunt/log4j-scan

## 모듈

- read-alerts.mjs: 시각·출발 주소·계정·수준·설명만 출력하며 비밀값을 지우고 한 경보마다 한 줄을 만듭니다.
- patterns.json: 이름·찾는 조건·근거·출처의 목록입니다.
- decide.mjs: 상단에 동일 패턴 상수를 두고 {action,confidence,reason}만 반환합니다. 입력과 순서에 의존하는 상태를 변경하지 않습니다.
- respond.mjs: 신뢰된 경보의 판단을 다시 계산합니다. 명확한 후보에만 만료 시각과 근거 경보 ID가 있는 추가 거부 규칙을 쓰고 xdr/alerts.log에 제한된 필드만 기록합니다.
- createVaultXdrGate: 기존 src/decider.mjs를 호출하는 추가 게이트입니다. 요청과 기존 결정은 보존합니다.

현재 18개 필드의 엔진 요청에는 출발 주소가 없습니다. 서버가 확인한 주소를 반환하는 콜백과 운영 등록부의 거부 응답 콜백이 필요합니다.
브라우저 헤더·본문의 sourceIp를 그 신뢰된 주소로 취급하지 않습니다. 파일 쓰기는 decide 밖에서만 수행합니다.
이 구현은 로컬 파일 저장소의 한 프로세스에서 순차 쓰기와 원자적 교체를 사용합니다. 분산 운영 저장소와 실제 반 엔진 연결을 완료했다고 주장하지 않습니다.

## 확인 결과

공식 fixture 바이트는 그대로이며 Git blob SHA는 d0f444a98e457a579fbce613012485d49936b17c입니다.
24건에서 block 8 · alert 8 · record 8입니다. 정상 8건 block 0입니다.
가상 재생은 8개 공격 후보를 거부하고 정상 8개를 모의 기본 허용 정책에 전달합니다.
이것은 모의 재생이며 현재 실제 판정기의 모든 정상 요청이 허용됐다는 뜻은 아닙니다.
단독 VM에서 decide.mjs 한 파일의 import를 거부하고 Node 전역·네트워크·파일 API 없이 24건을 다시 계산했습니다.
새 경보 번호·주소·헤더·URL 인코딩, 불완전한 입력, 비밀값 제외, 규칙 만료·중복, 기존 판정 보존을 시험했습니다.

## 재현

1. npm run xdr:cve:read — 경보 24건과 뽑은 줄 24개.
2. npm run xdr:run -- known-cve — result.json 갱신.
3. npm run xdr:cve:respond — 가상 시각 재생, normalBlocked 0.
4. node --test test/xdr-known-cve.test.mjs — 과제별 8개 시험.
5. npm test — 앞 단계와 기존 XDR 회귀 시험.

시뮬레이션 규칙은 xdr/runtime/known-cve-deny-rules.json, 감사 로그는 xdr/alerts.log에 있으며 Git에서 제외합니다.
재생에 쓰는 경보는 오래된 가상 사건입니다. 실제 시각에 그대로 집행하면 respond는 오래된 경보로 보고 차단 규칙을 만들지 않습니다.
심판은 공개 저장소의 xdr/known-cve/decide.mjs를 단독 실행합니다. result.json만으로 통과를 주장하지 않습니다.
