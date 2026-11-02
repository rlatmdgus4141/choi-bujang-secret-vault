// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions }) {
      const root = document.createElement('section');
      const deviceStatus = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionStatus = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      const shown = value => typeof value === 'string' && value.trim() !== ''
        ? value : typeof value === 'number' && Number.isFinite(value) ? String(value) : '확인 불가';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
      };
      const showDevice = (parent, title, device) => {
        const status = Object.hasOwn(deviceStatus, device?.status)
          ? deviceStatus[device.status] : deviceStatus.unknown;
        appendText(parent, 'p', `${title}: ${shown(device?.label)} · 기기 ID: ${shown(device?.id)} · ${status}`);
      };
      const showSession = (parent, title, session) => {
        const status = Object.hasOwn(sessionStatus, session?.status)
          ? sessionStatus[session.status] : sessionStatus.unknown;
        appendText(parent, 'p', `${title}: ${shown(session?.id)} · ${status}`);
      };
      const showResource = (title, resource, renderData) => {
        const section = document.createElement('section');
        appendText(section, 'h3', title);
        if (resource && Object.hasOwn(modes, resource.mode)) {
          appendText(section, 'p', modes[resource.mode]);
        }
        if (resource?.status === 'loading') {
          appendText(section, 'p', '불러오는 중');
        } else if (resource?.status === 'error') {
          appendText(section, 'p', `연결 실패: ${shown(resource.error?.message)}`);
        } else if (resource?.status === 'ok') {
          renderData(section, resource.data);
        } else {
          appendText(section, 'p', '확인 불가');
        }
        root.appendChild(section);
      };

      showResource('현재 계정', me, (section, data) => {
        appendText(section, 'p', `사용자: ${shown(data?.user?.label)} · 사용자 ID: ${shown(data?.user?.id)}`);
        showDevice(section, '현재 기기', data?.device);
        showSession(section, '현재 세션', data?.session);
      });
      showResource('기기 목록', devices, (section, data) => {
        if (!Array.isArray(data)) {
          appendText(section, 'p', '확인 불가');
          return;
        }
        if (data.length === 0) appendText(section, 'p', '항목 없음');
        for (const device of data) showDevice(section, '기기', device);
      });
      showResource('세션 목록', sessions, (section, data) => {
        if (!Array.isArray(data)) {
          appendText(section, 'p', '확인 불가');
          return;
        }
        if (data.length === 0) appendText(section, 'p', '항목 없음');
        for (const session of data) showSession(section, '세션', session);
      });
      return root;
    },
    renderDecision({ status, mode, data, error, appId }) {
      const root = document.createElement('section');
      const shown = value => typeof value === 'string' && value.trim() !== '' ? value : '확인 불가';
      const appendText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.appendChild(element);
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (typeof mode === 'string' && Object.hasOwn(modes, mode)) appendText('p', modes[mode]);
      if (status === 'idle') {
        appendText('p', '앱을 골라 접속을 요청하세요.');
        return root;
      }
      appendText('p', `요청 앱 ID: ${shown(status === 'ok' ? data?.appId ?? appId : appId)}`);
      if (status === 'loading') {
        appendText('p', '판정 확인 중');
      } else if (status === 'error') {
        appendText('p', `요청 실패: ${shown(error?.message)}`);
        appendText('p', '요청 실패는 접근 거부 판정이 아닙니다. 판정 결과를 확인할 수 없습니다.');
      } else if (status === 'ok') {
        const decisions = {
          allow: '접근 허용(allow)',
          deny: '접근 거부(deny)',
          challenge: '추가 확인 필요(challenge)',
          unknown: '판정 확인 불가(unknown)',
        };
        const decision = typeof data?.decision === 'string' && Object.hasOwn(decisions, data.decision)
          ? data.decision : 'unknown';
        appendText('h3', decisions[decision]);
        appendText('p', `판정 이유: ${shown(data?.reason)}`);
        appendText('p', `판정 시각: ${shown(data?.checkedAt)}`);
        if (decision === 'allow') {
          appendText('p', '정책상 접근 허용이며, 실제 앱 접속 성공을 보장하지 않습니다.');
        } else if (decision === 'challenge') {
          appendText('p', '추가 인증 또는 확인이 필요합니다. 이 앱은 확인 절차를 대신 수행하지 않습니다.');
        }
      } else {
        appendText('p', '요청 상태 확인 불가');
      }
      return root;
    },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
