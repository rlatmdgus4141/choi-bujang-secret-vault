# 케셰브 · 학생 구현 README

케셰브(KESHEV)는 직원 본인의 로그인 사용자·기기·현재 세션, 업무 앱 접근 판정, 최근 접속 기록과 저장된 XDR 경보를 확인하는 수업용 보안 Agent입니다. AI 설명은 참고 정보이며, 조치 제안·서버 접수·실제 효과 관측을 구분합니다.

이 README와 [학생용 실행 설명서 및 시스템 구성도](../docs/STUDENT_RUNBOOK.md)는 **21단계 학생 작성 문서**입니다. 저장소 루트 README의 1~12단계 자료실 이력과 `on-client/README.md` 등 시작 틀의 제공 문서는 그대로 보존했습니다. 이 앱의 실행 작업 위치는 `on-client`입니다.

## 기준 코드와 지원 환경

- 코드 기준 커밋: `6b54780c272d3b460c711e8aa9b791139dc8650f`(20단계). 21단계에서는 문서만 추가합니다.
- 시작 틀·앱 패키지: `on-client/package.json`의 `alekov-client-starter`, 버전 `0.2.14`. 파일·함수·실행 도구 이름은 유지합니다.
- 사용자 PC 확인 기록: Windows PowerShell, Node.js `v24.19.0`, Git `2.56.0.windows.4`. Windows·PowerShell·브라우저의 정확한 버전은 미확인입니다.
- 제공 실행 도구는 Node.js 주 버전 22~24를 허용하지만, 이번 PC 실행 기록과 `package.json`의 기준은 `24.19.0`입니다.
- AI의 개발 검사 환경은 Node.js `v24.22.1`입니다. 문법·모의 DOM·일부 루프백 HTTP 검사이며 Windows 앱 실행 전체를 인증한 결과가 아닙니다.
- `on-client/package.json`에는 외부 npm 의존성이 없고 이 폴더에는 `package-lock.json`이 없습니다. 현재 로컬 앱 실행에 별도 npm 패키지 설치가 필수는 아닙니다. 저장소 루트의 과거 자료실 설치·bundle 절차와 구분합니다.

## 실행 위치와 명령

현재 사용한 Git 최상위 폴더는 `$env:USERPROFILE\keshev-defense`, 앱 폴더는 그 아래 `on-client`입니다. 파일 탐색기에서 앱 폴더를 열고 주소 표시줄에 `powershell`을 입력해 새 창을 열 수 있습니다.

아래 명령은 사용자 PC에서 서버 시작 메시지까지 확인한 실행 방식입니다. 한글 사용자 경로에서 계정 연결 설정 경로 오류가 났을 때도 제공 파일 수정 없이 이 방식으로 시작됐습니다.

```powershell
Set-Location "$env:USERPROFILE\keshev-defense\on-client"
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); & .\tools\start-alekov.ps1"
```

브라우저 주소: [http://127.0.0.1:5189/](http://127.0.0.1:5189/). 종료는 실행 창에서 **Ctrl+C**, 재실행은 같은 폴더에서 같은 명령을 사용합니다. 서버 응답은 계정·SDP·AI 연결 성공이나 단계 통과를 뜻하지 않습니다.

## 학생이 구현한 기능

학생 화면 코드는 `on-client/student/extension.mjs`의 `createStudentView()`가 반환하는 아래 여덟 함수입니다. 제공 화면이 넘기는 입력을 받아 DOM을 만들며, 표시·필터·상세 선택·사용자 클릭에 따른 안전한 진단 정보 복사를 담당합니다.

| 단계 | 함수 | 학생 구현 내용 |
|---|---|---|
| 13 | `renderIdentity` | 사용자·기기·세션을 따로 표시하고 로딩·오류·예제 모드를 구분합니다. |
| 14 | `renderDecision` | 선택한 앱의 allow·deny·challenge·unknown과 요청 실패, 이유·시각을 구분합니다. |
| 15 | `renderEvents` | 받은 본인 기록을 최신순으로 정렬하고 세 필터와 근거·규칙·상태 상세를 표시합니다. |
| 16 | `renderStatus` | 기기·세션의 빈 상태·실패·알림·진단 정보를 구분하고 지정된 여섯 진단 필드만 복사합니다. |
| 17 | `renderAiConnection` | 모델 목록 점검과 실제 사건 설명을 구분하고 오류별 수동 복구 방향을 표시합니다. |
| 18 | `renderExplanation` | 선택한 기록의 근거 ID에 연결된 AI 요약·규칙·확인 불가 상태·미실행 제안을 표시합니다. |
| 19 | `renderAction` | 준비·전송·ACK·결과 불명과 실제 효과 관측을 구분합니다. 학생 조치 요청 버튼은 만들지 않습니다. |
| 20 | `renderVulnerabilities` | 정확한 버전·출처·시각·lock 해시·OSV 상태를 표시하고 부분 실패의 취약점 ID를 보존합니다. |

## 제공 코드와 학생 코드 경계

`public/app.js`의 메뉴·API 요청·취소·재조회·응답 검증과 `src/`의 서버·인증·SDP·AI·조치·OSV 모듈은 제공 기능입니다. `student/engine-adapter.mjs`도 제공 파일이며, 학생 폴더 안에 있다는 이유로 직접 구현했다고 보지 않습니다. 제공/학생 파일 목록의 출발점은 `on-client/.on-starter-manifest.json`의 `sourceHashes`입니다.

학생 함수에 확인 티켓·비밀번호·토큰·API 키를 추가하거나, 제공 서버·인증 설정을 변경하지 않았습니다. 제공 AI 공통 모듈의 출처는 `on-client/vendor/NOTICE.md`를 따르며 새로운 공개 라이선스를 선언하지 않습니다.

## 확인 범위와 다음 절차

사용자 PC에서 13~15단계의 예제·오류 화면과 기존 값 제거를 확인한 기록이 있습니다. 16~20단계는 코드·모의 입력 및 일부 로컬 API로 검사했습니다. 실제 직원 계정의 SDP·AI 게이트 연결, 유료 사건 설명, 실제 보안 조치와 외부 OSV 조회 결과는 **미확인·기다림(UNV)**입니다. 구체적인 증거 구분·구성도·장애 복구 표는 [실행 설명서](../docs/STUDENT_RUNBOOK.md)에 있습니다.

21·22단계는 과제 화면에 저장소 주소와 새 40자리 커밋을 직접 입력합니다. 서버 AI는 커밋의 문서·소스·설정 견본을 읽으며 명령을 실행해 인증하지 않습니다. 비공개 커밋은 해당 단계의 원문 전달 도구 안내를 따릅니다. 기존 제공 문서의 21·22단계 미확정 문구보다 이번 공식 과제 안내를 우선합니다.
