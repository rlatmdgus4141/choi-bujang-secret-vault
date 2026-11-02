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
    renderEvents({ status, mode, data, error }) {
      const root = document.createElement('section');
      const shown = value => typeof value === 'string' && value.trim() !== '' ? value : '확인 불가';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (typeof mode === 'string' && Object.hasOwn(modes, mode)) appendText(root, 'p', modes[mode]);
      if (status === 'loading') {
        appendText(root, 'p', '기록을 불러오는 중입니다.');
        return root;
      }
      if (status === 'error') {
        if (error?.code === 'CONTRACT_MISMATCH') appendText(root, 'p', '기록 확인 불가');
        appendText(root, 'p', `기록을 불러오지 못했습니다: ${shown(error?.message)}`);
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        appendText(root, 'p', '기록 확인 불가: 전달된 목록을 확인할 수 없습니다.');
        return root;
      }
      const kindNames = { access: '접속 기록', xdr: 'XDR 경보', unknown: '확인 불가' };
      const describe = (names, value) => {
        const code = typeof value === 'string' && Object.hasOwn(names, value) ? value : 'unknown';
        return `${names[code]}(${code})`;
      };
      const appLabel = value => typeof value === 'string' && value.trim() !== '' ? value : '앱 확인 불가';
      const timestamp = event => {
        const value = Date.parse(event.at);
        return Number.isFinite(value) ? value : -Infinity;
      };
      const events = [...data].sort((a, b) => timestamp(b) - timestamp(a));
      appendText(root, 'p', '서버에서 받은 본인 기록만 표시합니다. XDR 경보는 저장된 기록입니다.');
      const accessNames = { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' };
      const sessionNames = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const deviceNames = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const filters = document.createElement('fieldset');
      appendText(filters, 'legend', '기록 필터');
      root.appendChild(filters);
      const makeFilter = (name, values, labelFor) => {
        const line = document.createElement('div');
        const label = document.createElement('label');
        appendText(label, 'span', `${name} `);
        const select = document.createElement('select');
        select.setAttribute('aria-label', name);
        const all = appendText(select, 'option', '전체');
        all.value = 'all';
        for (const value of new Set(values)) {
          if (typeof value !== 'string' || value.trim() === '' || value === 'all') continue;
          const option = appendText(select, 'option', labelFor(value));
          option.value = value;
        }
        select.value = 'all';
        label.appendChild(select);
        line.appendChild(label);
        filters.appendChild(line);
        return select;
      };
      const kindFilter = makeFilter('기록 종류', events.map(event => event.kind), value => describe(kindNames, value));
      const appFilter = makeFilter('업무 앱', events.map(event => event.appId), appLabel);
      const accessFilter = makeFilter('접속 상태', events.map(event => event.state?.access), value => describe(accessNames, value));
      const count = appendText(root, 'p', '');
      const list = document.createElement('ul');
      root.appendChild(list);
      const detailHost = document.createElement('div');
      root.appendChild(detailHost);
      const showEntries = (parent, title, entries) => {
        const group = document.createElement('section');
        appendText(group, 'h4', title);
        parent.appendChild(group);
        if (!Array.isArray(entries)) {
          appendText(group, 'p', `${title} 확인 불가`);
        } else if (entries.length === 0) {
          appendText(group, 'p', `제공된 ${title} 항목이 없습니다.`);
        } else {
          const entriesList = document.createElement('ul');
          for (const entry of entries) appendText(entriesList, 'li', `${title} ID: ${shown(entry?.id)} · ${shown(entry?.text)}`);
          group.appendChild(entriesList);
        }
      };
      const showDetail = event => {
        const detail = document.createElement('section');
        detail.setAttribute('data-student-event-detail', event.id);
        appendText(detail, 'h3', '기록 상세');
        appendText(detail, 'p', `사건 ID: ${shown(event.id)}`);
        appendText(detail, 'p', `업무 앱: ${appLabel(event.appId)}`);
        showEntries(detail, '근거', event.evidence);
        showEntries(detail, '규칙', event.rules);
        appendText(detail, 'p', `접속 상태: ${describe(accessNames, event.state?.access)}`);
        appendText(detail, 'p', `세션 상태: ${describe(sessionNames, event.state?.session)}`);
        appendText(detail, 'p', `기기 상태: ${describe(deviceNames, event.state?.device)}`);
        detailHost.replaceChildren(detail);
      };
      const renderList = () => {
        const visible = events.filter(event =>
          (kindFilter.value === 'all' || event.kind === kindFilter.value)
          && (appFilter.value === 'all' || event.appId === appFilter.value)
          && (accessFilter.value === 'all' || event.state?.access === accessFilter.value));
        count.textContent = `표시: ${visible.length}건 / 받은 기록: ${events.length}건`;
        list.replaceChildren();
        detailHost.replaceChildren();
        if (visible.length === 0) appendText(list, 'li', events.length === 0 ? '표시할 기록이 없습니다' : '필터 조건에 맞는 기록이 없습니다');
        for (const event of visible) {
          const row = document.createElement('li');
          row.setAttribute('data-student-event-id', event.id);
          appendText(row, 'p', `사건 ID: ${shown(event.id)}`);
          appendText(row, 'p', `시각: ${shown(event.at)}`);
          appendText(row, 'p', `종류: ${describe(kindNames, event.kind)}`);
          appendText(row, 'p', `업무 앱: ${appLabel(event.appId)}`);
          appendText(row, 'p', `요약: ${shown(event.summary)}`);
          const button = appendText(row, 'button', `${shown(event.id)} 상세`);
          button.type = 'button';
          button.className = 'btn';
          button.addEventListener('click', () => showDetail(event));
          list.appendChild(row);
        }
      };
      for (const select of [kindFilter, appFilter, accessFilter]) select.addEventListener('change', renderList);
      renderList();
      return root;
    },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
