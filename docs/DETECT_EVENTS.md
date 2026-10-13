# 9단계 탐지 연습 사건 계약

`npm run detect:test`는 학생이 작성한 `src/detect.mjs`의 `detect(events)`에 가상 조회 사건을 전달합니다. 각 사건은 다음 세 값만 가집니다.

```js
{ at: '2026-10-01T00:00:00.000Z', method: 'GET', identity: { sub: 'learner_fixture' } }
```

같은 `identity.sub`의 `GET` 사건이 어느 10분 구간에서든 **120건을 넘을 때만** `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: '해당 sub' }`를 돌려줍니다. 그 밖에는 `{ action: 'observe' }`입니다. 정확히 120건은 회수 제안 대상이 아닙니다. 다른 사용자의 사건을 합산하거나 10분 밖의 사건을 같은 묶음으로 세지 않습니다.

이 파일의 사건 모양은 **로컬 연습용**입니다. 브라우저가 보낸 사용자 번호를 신원으로 취급하지 않습니다. 운영 반 엔진이 검증한 사건을 전달하고 회수 제안을 집행하는 경로는 별도로 연결·시험해야 합니다. 이 명령의 통과를 실제 접속 차단이나 심판 판정으로 표시하지 않습니다.

## 9단계 복합 기기 사건의 로컬 확인

위의 세 항목은 원본 공개 시작 틀의 연습 계약으로 보존합니다. 이 계약에는 기기·네트워크 정보가 없으므로
사용자 조회 폭주를 제안하는 연습 결과이며 기기별 실제 회수 완료로 표시하지 않습니다.
`npm run detect:test`는 기존 6건과 기기 정보가 있는 로컬 복합 사건 6건을 함께 실행합니다.

기기별 확인에는 기존 판정 요청에서 알려진 가명 주체·deviceId·signals와 판정 값을 사용한 아래 모의 입력을 더합니다.
새 운영 반 엔진의 사건 계약이 제공되었다는 뜻은 아니며, 실제 전달·집행 연결은 심판이 확인합니다.

```js
{
  at: '2026-10-01T00:00:00.000Z', method: 'GET',
  classId: 'class_fixture', projectId: 'project_fixture',
  subjectId: 'learner_fixture', deviceId: 'aaaaaaaaaaaaaaaa',
  decision: 'allow',
  signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 14 }
}
```

가명 주체는 subjectId 또는 기존 identity.sub로 읽으며, 두 값이 서로 다르면 세지 않습니다.
기기 식별자는 기존 요청 계약의 소문자 16자리 16진수입니다. 판정은 allow·deny·step_up만 읽습니다.
주체·기기·반·프로젝트별로 나누고, network가 unusual인 조회 요청이 같은 10분 구간에서 120건을 넘을 때만 제안합니다.
지역 하나나 업무 시각 하나는 근거로 쓰지 않습니다. 기기·네트워크·판정이 누락되거나 출처가 불명확하면 정상값을 만들어 넣지 않습니다.
제안은 한 개의 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId }`이고 나머지는 `{ action: 'observe' }`입니다.
다른 사용자·기기와 평소 네트워크 요청을 합산하지 않습니다. 복합 입력과 이전 연습 입력을 섞어 강도를 높이지 않습니다.
requestId가 있으면 중복을 한 번만 세고, 같은 번호의 내용이 충돌하면 해당 번호를 제외합니다.
이전 연습 입력에는 고유 사건 번호가 없으므로 그 형식에서 중복 전달을 구분했다고 주장하지 않습니다.

readDetectionEvents는 시각·가명 주체·기기·메서드·판정과 필요한 상관 항목만 메모리에서 읽습니다.
메모 본문·토큰·헤더·실명은 복사하지 않으며 저장/로그/네트워크/회수 API를 추가하지 않습니다.
출처 표시는 암호학적 신원 검증을 대신하지 않습니다. 이 함수는 신뢰된 서버 호출 전용이며 브라우저가 직접 사건을 입력하는 경로가 없습니다.
접속 판정기 응답 다섯 항목은 보존하고, 실제 회수 후 재접속 거부와 경과 시간은 운영 심판 시험으로 확인합니다.
