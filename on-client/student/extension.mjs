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
        const unsupportedActions = Array.isArray(event.supportedActions)
          ? event.supportedActions.filter(action => typeof action === 'string' && action.trim() !== '') : [];
        if (unsupportedActions.length > 0) {
          appendText(detail, 'p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중입니다.');
          for (const action of unsupportedActions) {
            const button = appendText(detail, 'button', `${action} 미지원`);
            button.type = 'button';
            button.className = 'btn';
            button.disabled = true;
          }
        }
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
    renderStatus({ devices, sessions, notifications, diagnostics, mode }) {
      const root = document.createElement('section');
      const shown = value => typeof value === 'string' && value.trim() !== '' ? value : '확인 불가';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      const showMode = (parent, value) => {
        if (typeof value === 'string' && Object.hasOwn(modes, value)) appendText(parent, 'p', modes[value]);
      };
      const describe = (names, value) => {
        const code = typeof value === 'string' && Object.hasOwn(names, value) ? value : 'unknown';
        return `${names[code]}(${code})`;
      };
      const makeSection = title => {
        const section = document.createElement('section');
        appendText(section, 'h3', title);
        root.appendChild(section);
        return section;
      };
      const showFailure = (parent, title, error, retry) => {
        const timeout = typeof error?.code === 'string' && error.code.toUpperCase().includes('TIMEOUT');
        appendText(parent, 'p', `${title}를 불러오지 못했습니다${timeout ? '(시간 초과)' : ''}: ${shown(error?.message)}`);
        appendText(parent, 'p', retry);
      };
      const reloadGuide = '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.';
      const deviceNames = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const sessionNames = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      showMode(root, mode);
      const showList = (title, resource, emptyText, renderItem) => {
        const section = makeSection(title);
        showMode(section, resource?.mode);
        if (resource?.status === 'loading') {
          appendText(section, 'p', `${title}를 불러오는 중입니다.`);
        } else if (resource?.status === 'error') {
          showFailure(section, title, resource.error, reloadGuide);
        } else if (resource?.status === 'ok' && Array.isArray(resource.data)) {
          if (resource.data.length === 0) appendText(section, 'p', emptyText);
          const list = document.createElement('ul');
          for (const item of resource.data) appendText(list, 'li', renderItem(item));
          section.appendChild(list);
        } else if (resource?.status === 'idle') {
          appendText(section, 'p', `${title}는 아직 불러오지 않았습니다.`);
          appendText(section, 'p', reloadGuide);
        } else {
          appendText(section, 'p', `${title} 확인 불가`);
          appendText(section, 'p', reloadGuide);
        }
        return section;
      };
      showList('기기 정보', devices, '등록된 기기가 없습니다.', device =>
        `기기: ${shown(device?.label)} · 기기 ID: ${shown(device?.id)} · 상태: ${describe(deviceNames, device?.status)}`);
      const sessionSection = showList('세션 정보', sessions, '현재 연결이 없습니다.', session =>
        `세션 ID: ${shown(session?.id)} · 상태: ${describe(sessionNames, session?.status)}`);
      appendText(sessionSection, 'p', '세션 조회 범위는 현재 검증된 연결 하나입니다. 과거 세션 전체 목록은 제공하지 않습니다.');

      const alerts = makeSection('알림');
      if (!Array.isArray(notifications)) {
        appendText(alerts, 'p', '알림 확인 불가');
      } else if (notifications.length === 0) {
        appendText(alerts, 'p', '주의할 알림이 없습니다.');
      } else {
        const list = document.createElement('ul');
        for (const notification of notifications) {
          appendText(list, 'li', `자료(resource): ${shown(notification?.resource)} · 코드(code): ${shown(notification?.code)} · 내용: ${shown(notification?.message)}`);
        }
        alerts.appendChild(list);
      }

      const help = makeSection('진단 정보');
      showMode(help, diagnostics?.mode);
      appendText(help, 'p', '도움 요청에 사용할 진단 정보입니다. 표시된 여섯 필드만 사용자가 눌렀을 때 복사합니다.');
      const diagnosticGuide = '진단 정보를 다시 확인하려면 제공 화면의 도움정보 불러오기 버튼을 직접 누르세요.';
      let helpText = '';
      if (diagnostics?.status === 'loading') {
        appendText(help, 'p', '진단 정보를 불러오는 중입니다.');
      } else if (diagnostics?.status === 'error') {
        showFailure(help, '진단 정보', diagnostics.error, diagnosticGuide);
      } else if (diagnostics?.status === 'ok') {
        const data = diagnostics.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) {
          appendText(help, 'p', '진단 정보 확인 불가');
        } else if (![data.requestId, data.component, data.version, data.checkedAt, data.engine?.mode, data.engine?.code]
          .some(value => typeof value === 'string' && value.trim() !== '')) {
          appendText(help, 'p', '표시할 진단 정보가 없습니다.');
        } else {
          const safeInfo = {
            requestId: shown(data.requestId),
            component: shown(data.component),
            version: shown(data.version),
            checkedAt: shown(data.checkedAt),
            engine: { mode: shown(data.engine?.mode), code: shown(data.engine?.code) },
          };
          helpText = JSON.stringify(safeInfo, null, 2);
          const output = appendText(help, 'pre', helpText);
          output.tabIndex = 0;
        }
      } else if (diagnostics?.status === 'idle') {
        appendText(help, 'p', '진단 정보는 아직 불러오지 않았습니다.');
        appendText(help, 'p', diagnosticGuide);
      } else {
        appendText(help, 'p', '진단 정보 확인 불가');
        appendText(help, 'p', diagnosticGuide);
      }
      const copy = appendText(help, 'button', '도움정보 복사');
      copy.type = 'button';
      copy.className = 'btn';
      copy.disabled = helpText === '';
      const copyStatus = appendText(help, 'p', '');
      copyStatus.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        if (!helpText || copy.disabled) return;
        copy.disabled = true;
        copyStatus.textContent = '도움정보를 복사하는 중입니다.';
        try {
          await globalThis.navigator.clipboard.writeText(helpText);
          copyStatus.textContent = '도움정보를 클립보드에 복사했습니다.';
        } catch {
          copyStatus.textContent = '복사하지 못했습니다. 표시된 진단 정보를 직접 선택해 Ctrl+C로 복사하세요.';
        } finally {
          copy.disabled = false;
        }
      });
      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted }) {
      const root = document.createElement('section');
      const shown = value => typeof value === 'string' && value.trim() !== '' ? value : '확인 불가';
      const appendText = (tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        root.appendChild(element);
      };
      const modes = {
        demo: '예제 자료(demo) · 실제 계정의 연결 성공을 뜻하지 않습니다.',
        disconnected: '연결 없음(disconnected)',
        unknown: '확인 불가(unknown)',
      };
      if (typeof mode === 'string' && Object.hasOwn(modes, mode)) appendText('p', modes[mode]);
      if (status === 'idle') {
        appendText('h3', 'AI 연결 점검 전');
      } else if (status === 'loading') {
        appendText('h3', 'AI 연결 점검 중');
      } else if (status === 'ok') {
        const authorizations = { test: '시험 연결 점검(test)', verified: '앱 권한 확인 후 점검(verified)' };
        const valid = data?.transportChecked === true
          && typeof data.audienceAuthorization === 'string' && Object.hasOwn(authorizations, data.audienceAuthorization)
          && Number.isInteger(data.modelCount) && data.modelCount >= 0;
        if (valid) {
          appendText('h3', authorizations[data.audienceAuthorization]);
          appendText('p', `응답 모델 수(modelCount): ${data.modelCount}`);
          appendText('p', `점검 시각(checkedAt): ${shown(checkedAt)}`);
          if (data.audienceAuthorization === 'test') appendText('p', '시험 연결 결과입니다. 실제 앱 이용 권한이 확인됐다는 뜻은 아닙니다.');
          if (data.modelCount === 0) appendText('p', '응답 모델 수가 0입니다. 담당자에게 사용할 수 있는 모델의 허용 설정을 확인해 달라고 요청하세요.');
        } else {
          appendText('h3', 'AI 연결 점검 결과 확인 불가');
          appendText('p', '전달된 점검 결과의 형식을 확인할 수 없습니다. 담당자에게 계정 연결과 앱 권한을 확인해 달라고 요청하세요.');
        }
      } else if (status === 'error') {
        appendText('h3', 'AI 연결 점검 실패');
        appendText('p', `오류 코드: ${shown(error?.code)}`);
        appendText('p', `오류 내용: ${shown(error?.message)}`);
        const guidance = {
          pending: '권한 준비 중 또는 확인 불가입니다. 담당자에게 계정 연결과 앱 권한을 확인해 달라고 요청하세요. 운영 권한 준비는 학생 코드 수정으로 해결할 수 없습니다.',
          changed: '점검 도중 이용 권한이 변경됐습니다. 담당자에게 현재 권한을 확인한 뒤 직접 다시 점검하세요.',
          auth: '인증 실패입니다. 계정 연결을 다시 확인하고 담당자에게 앱 인증 상태 확인을 요청하세요.',
          blocked: '접근이 제한됐습니다. 계정 연결과 앱 이용 권한을 담당자에게 확인하세요.',
          budget: '반 사용량 또는 이용 한도에 도달했습니다. 담당자에게 사용량과 이용 한도를 확인하세요.',
          hours: '현재 이용 시간이 아닙니다. 담당자에게 AI 이용 시간을 확인하세요.',
          rate: '요청이 일시적으로 제한됐습니다. 잠시 뒤 직접 다시 점검하세요.',
          timeout: '시간 초과로 점검 결과를 확인하지 못했습니다. 잠시 뒤 직접 다시 점검하세요.',
          network: '서버 응답 또는 네트워크 연결을 확인할 수 없습니다. 연결 상태를 확인한 뒤 잠시 후 직접 다시 점검하세요.',
          cancelled: 'AI 연결 점검이 취소됐습니다. 이전 응답과 모델 수는 현재 결과가 아닙니다. 필요하면 직접 다시 점검하세요.',
          model: '사용할 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인해 달라고 요청하세요.',
        };
        const groups = [
          [['ON_AI_PROVISIONING_PENDING', 'ON_AI_TRANSPORT_PENDING', 'AI_REQUEST_UNVERIFIED', 'SUBJECT_SCOPE_UNVERIFIED'], 'pending'],
          [['ON_AI_AUTHORIZATION_CHANGED'], 'changed'],
          [['WB_CLCO_AUTH_REQUIRED', 'WB_CLCO_INVALID_TOKEN'], 'auth'],
          [['WB_CLCO_ACCESS_BLOCKED'], 'blocked'],
          [['WB_CLCO_COHORT_BUDGET_EXHAUSTED', 'WB_CLCO_LIMIT_REACHED'], 'budget'],
          [['WB_CLCO_SESSION_CLOSED'], 'hours'],
          [['WB_CLCO_RATE_LIMITED'], 'rate'],
          [['WB_CLCO_TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT', 'TIMEOUT'], 'timeout'],
          [['WB_CLCO_NETWORK_ERROR', 'WB_CLCO_SERVER_UNAVAILABLE', 'NETWORK_ERROR'], 'network'],
          [['WB_CLCO_CANCELLED', 'REQUEST_CANCELLED', 'CANCELLED'], 'cancelled'],
          [['MODEL_NOT_CONFIGURED', 'ON_AI_MODEL_LIST_EMPTY'], 'model'],
        ];
        const group = groups.find(([codes]) => codes.includes(error?.code))?.[1] ?? 'pending';
        appendText('p', guidance[group]);
      } else {
        appendText('h3', 'AI 연결 점검 상태 확인 불가');
      }
      appendText('p', '이 연결 점검으로 사건 설명을 실행하지 않았습니다. 사건 설명은 보안 기록에서 별도로 요청하고 확인하세요.');
      appendText('p', '다시 점검하려면 제공 화면의 현재 API 연결 점검 버튼을 직접 누르세요.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt }) {
      const root = document.createElement('section');
      const shown = value => typeof value === 'string' && value.trim() !== '' ? value : '확인 불가';
      const isText = value => typeof value === 'string' && value.trim() !== '';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const unusable = reason => {
        appendText(root, 'h3', 'AI 설명을 사용할 수 없습니다');
        appendText(root, 'p', reason);
        if (isText(explanation?.error?.code)) appendText(root, 'p', `오류 코드: ${explanation.error.code}`);
        appendText(root, 'p', '기록은 그대로 유지됩니다. AI 설명의 실패는 과제 실패를 뜻하지 않습니다.');
        return root;
      };
      if (explanation?.mode === 'demo') appendText(root, 'p', '예제 자료(demo) · 실제 계정의 사건 설명 결과가 아닙니다.');
      if (explanation?.status === 'error') {
        appendText(root, 'h3', 'AI 설명 실패');
        appendText(root, 'p', `오류 코드: ${shown(explanation.error?.code)}`);
        appendText(root, 'p', `오류 내용: ${shown(explanation.error?.message)}`);
        appendText(root, 'p', '기록은 그대로 유지됩니다. AI 설명의 실패는 과제 실패를 뜻하지 않습니다.');
        return root;
      }
      if (!event) {
        appendText(root, 'p', '보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        appendText(root, 'p', `사건 ID: ${shown(event.id)}`);
        appendText(root, 'p', 'AI 설명 요청 중입니다.');
        return root;
      }
      if (explanation?.status === 'idle') {
        appendText(root, 'p', `사건 ID: ${shown(event.id)}`);
        appendText(root, 'p', '사건 설명은 아직 요청하지 않았습니다. 보안 기록의 AI 설명 요청 버튼을 직접 눌러 요청하세요.');
        return root;
      }
      if (explanation?.status !== 'ok') return unusable('사건 설명 상태를 확인할 수 없습니다.');
      const data = explanation.data;
      if (data?.executed === true) return unusable('AI가 조치를 이미 실행했다고 응답한 설명은 사용할 수 없습니다. 실제 실행 여부는 연동 시스템에서 확인해야 합니다.');
      if (!isText(event.id) || !isText(data?.summary)) return unusable('사건 ID 또는 설명 요약을 확인할 수 없습니다.');
      if (data.executed !== false || data.requiresHumanConfirmation !== true) return unusable('사람 확인 필요 여부 또는 조치의 미실행 상태를 확인할 수 없습니다.');
      const validRows = rows => Array.isArray(rows) && rows.length > 0
        && rows.every(row => isText(row?.id) && isText(row?.text))
        && new Set(rows.map(row => row.id)).size === rows.length;
      if (!validRows(event.evidence)) return unusable('근거가 부족하거나 근거 형식이 맞지 않아 설명을 확인할 수 없습니다.');
      if (!validRows(event.rules)) return unusable('규칙 정보가 부족하거나 형식이 맞지 않아 설명을 확인할 수 없습니다.');
      const evidence = new Map(event.evidence.map(row => [row.id, row.text]));
      const validRefs = refs => Array.isArray(refs) && refs.length > 0
        && new Set(refs).size === refs.length && refs.every(id => isText(id) && evidence.has(id));
      if (!validRefs(data.evidenceIds) || data.evidenceIds.length !== evidence.size) {
        return unusable('근거가 맞지 않습니다. 선택한 기록의 근거 ID와 설명의 인용 ID가 일치하지 않거나 빠진 근거가 있습니다.');
      }
      const states = { access: ['allowed', 'denied', 'unknown'], session: ['active', 'expired', 'revoked', 'unknown'], device: ['compliant', 'noncompliant', 'unknown'] };
      if (!Object.entries(states).every(([key, values]) => values.includes(event.state?.[key]))) return unusable('연동 시스템이 알려 준 현재 상태를 확인할 수 없습니다.');
      if (!Array.isArray(event.supportedActions) || !event.supportedActions.every(isText) || !Array.isArray(data.proposals)) return unusable('지원 조치 또는 제안 목록을 확인할 수 없습니다.');
      if (!data.proposals.every(proposal => isText(proposal?.action) && event.supportedActions.includes(proposal.action)
        && isText(proposal.reason) && validRefs(proposal.evidenceIds))) return unusable('지원하지 않는 조치가 있거나 제안의 근거 ID·이유가 선택한 기록과 맞지 않습니다.');

      root.setAttribute('data-student-explanation-event', event.id);
      appendText(root, 'h3', 'AI 설명(참고용)');
      appendText(root, 'p', `사건 ID: ${event.id}`);
      appendText(root, 'p', `AI 요약: ${data.summary}`);
      appendText(root, 'p', `확인 시각(checkedAt): ${shown(checkedAt)}`);
      appendText(root, 'p', 'AI 설명은 해석입니다. 사실 판단은 근거 글과 연동 시스템이 알려 준 상태를 기준으로 합니다.');
      const evidenceGroup = document.createElement('section');
      appendText(evidenceGroup, 'h4', '인용한 근거');
      const evidenceList = document.createElement('ul');
      for (const id of data.evidenceIds) appendText(evidenceList, 'li', `${id} — ${evidence.get(id)}`);
      evidenceGroup.appendChild(evidenceList);
      root.appendChild(evidenceGroup);
      const rulesGroup = document.createElement('section');
      appendText(rulesGroup, 'h4', '규칙');
      const rulesList = document.createElement('ul');
      for (const rule of event.rules) appendText(rulesList, 'li', `${rule.id} — ${rule.text}`);
      rulesGroup.appendChild(rulesList);
      root.appendChild(rulesGroup);
      const unknownGroup = document.createElement('section');
      appendText(unknownGroup, 'h4', '확인 불가 상태');
      const stateNames = { access: '접속', session: '세션', device: '기기' };
      const unknowns = Object.keys(stateNames).filter(key => event.state[key] === 'unknown');
      if (unknowns.length === 0) appendText(unknownGroup, 'p', '없음');
      else {
        const unknownList = document.createElement('ul');
        for (const key of unknowns) appendText(unknownList, 'li', `${stateNames[key]}: 확인 불가(unknown)`);
        unknownGroup.appendChild(unknownList);
      }
      root.appendChild(unknownGroup);
      const proposalsGroup = document.createElement('section');
      appendText(proposalsGroup, 'h4', '조치 제안');
      if (data.proposals.length === 0) {
        appendText(proposalsGroup, 'p', event.supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 제안한 조치가 없습니다.');
      } else {
        const list = document.createElement('ul');
        for (const proposal of data.proposals) {
          const row = document.createElement('li');
          appendText(row, 'p', `조치: ${proposal.action}`);
          appendText(row, 'p', `이유: ${proposal.reason}`);
          for (const id of proposal.evidenceIds) appendText(row, 'p', `제안 근거: ${id} — ${evidence.get(id)}`);
          appendText(row, 'p', '사람 확인이 필요하며 실행되지 않았습니다.');
          list.appendChild(row);
        }
        proposalsGroup.appendChild(list);
      }
      appendText(proposalsGroup, 'p', '설명과 제안만으로 보안 조치가 실행되지는 않습니다.');
      root.appendChild(proposalsGroup);
      return root;
    },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
