// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
// PC 조회는 학생 수집 파일만 읽습니다. 제공 서버·인증·보안 설정은 변경하지 않습니다.
function createPcDashboard() {
  const state = { status: 'idle', current: null, history: [], notice: '', loadId: 0 };
  let updateCurrent = () => {};
  let currentButton = null;
  const errors = {
    ACCESS_DENIED: '일반 권한으로 읽을 수 없습니다. 관리자 권한으로 전환하지 않고 확인 불가로 남깁니다.',
    COMMAND_UNAVAILABLE: '이 Windows 환경에서 필요한 조회 명령을 찾지 못했습니다.',
    VALUE_UNAVAILABLE: 'Windows가 유효한 측정값을 반환하지 않았습니다.',
    QUERY_FAILED: '로컬 조회에 실패했습니다. 일반 PowerShell에서 다시 수집하세요.',
    INVALID_FILE: '케셰브 수집 파일의 형식이나 값이 맞지 않습니다. 수집 도구로 새 파일을 만든 뒤 다시 조회하세요.',
    READ_FAILED: '수집 파일을 읽지 못했습니다. 접근 가능한 JSON 파일을 다시 선택하세요.',
    READ_TIMEOUT: '수집 파일 읽기 시간이 초과됐습니다. 파일을 다시 선택하세요.',
    OLD_FILE: '이전 표본보다 오래된 파일입니다. 새로 수집한 파일을 선택하세요.',
  };
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const time = value => typeof value === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
  const fail = () => { throw new Error('INVALID_FILE'); };
  const string = (value, max = 120) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) fail();
    return value;
  };
  const number = (value, min = 0, max = Number.MAX_SAFE_INTEGER) => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) fail();
    return value;
  };
  const array = (value, max) => {
    if (!Array.isArray(value) || value.length > max) fail();
    return value;
  };
  const error = value => {
    const code = object(value) && Object.hasOwn(errors, value.code) ? value.code : 'QUERY_FAILED';
    return { code, message: errors[code] };
  };
  function normalise(value) {
    if (!object(value) || value.schema !== 'keshev.pc-status.v1' || !object(value.source)
      || !['measured', 'example'].includes(value.source.mode)
      || value.source.kind !== (value.source.mode === 'measured' ? 'windows-powershell' : 'example')
      || typeof value.source.computerId !== 'string' || !/^[a-f0-9]{64}$/.test(value.source.computerId)
      || !time(value.startedAt) || !time(value.finishedAt) || Date.parse(value.finishedAt) < Date.parse(value.startedAt)) fail();
    const result = {
      source: { mode: value.source.mode, computerId: value.source.computerId },
      startedAt: value.startedAt, finishedAt: value.finishedAt,
    };
    const read = (name, unit, partial = false) => {
      const r = value[name];
      if (!object(r) || !(partial ? ['ok', 'partial', 'error'] : ['ok', 'error']).includes(r.status)
        || !time(r.checkedAt) || r.unit !== unit
        || Date.parse(r.checkedAt) < Date.parse(value.startedAt) - 1000
        || Date.parse(r.checkedAt) > Date.parse(value.finishedAt) + 1000) fail();
      const safe = { status: r.status, checkedAt: r.checkedAt, unit, error: error(r.error), data: null };
      if (r.status !== 'error' || name === 'events') {
        if (!object(r.data)) fail();
        safe.data = r.data;
      }
      return safe;
    };
    result.cpu = read('cpu', '%');
    if (result.cpu.data) result.cpu.data = { usagePercent: number(result.cpu.data.usagePercent, 0, 100) };
    result.memory = read('memory', 'GiB,%');
    if (result.memory.data) {
      const d = result.memory.data;
      const total = number(d.totalGiB, 0.001), used = number(d.usedGiB, 0, total);
      const percent = number(d.usagePercent, 0, 100);
      if (Math.abs(used / total * 100 - percent) > 1) fail();
      result.memory.data = { totalGiB: total, usedGiB: used, usagePercent: percent };
    }
    result.disks = read('disks', 'GiB,%', true);
    if (result.disks.data) {
      const d = result.disks.data;
      if (typeof d.systemDrive !== 'string' || !/^[A-Za-z]:$/.test(d.systemDrive)) fail();
      const seen = new Set();
      const items = array(d.items, 26).map(item => {
        if (!object(item) || typeof item.id !== 'string' || !/^[A-Za-z]:$/.test(item.id)
          || seen.has(item.id.toUpperCase()) || !['ok', 'error'].includes(item.status)) fail();
        seen.add(item.id.toUpperCase());
        if (item.status === 'error') return { id: item.id, status: 'error', error: error(item.error) };
        const total = number(item.totalGiB, 0.001), free = number(item.freeGiB, 0, total);
        const percent = number(item.freePercent, 0, 100);
        if (Math.abs(free / total * 100 - percent) > 1) fail();
        return { id: item.id, status: 'ok', totalGiB: total, freeGiB: free, freePercent: percent };
      });
      result.disks.data = { systemDrive: d.systemDrive, items };
    }
    result.network = read('network', '주소,상태', true);
    if (result.network.data) {
      const d = result.network.data;
      if (typeof d.truncated !== 'boolean') fail();
      const addresses = values => array(values, 64).map(value => string(value, 80));
      result.network.data = { truncated: d.truncated, items: array(d.items, 32).map(item => {
        if (!object(item)) fail();
        return { label: string(item.label), ipv4: addresses(item.ipv4), ipv6: addresses(item.ipv6),
          gateway: addresses(item.gateway), dns: addresses(item.dns) };
      }) };
    }
    result.firewall = read('firewall', '상태');
    if (result.firewall.data) {
      const seen = new Set();
      result.firewall.data = { items: array(result.firewall.data.items, 3).map(item => {
        if (!object(item) || !['Domain', 'Private', 'Public'].includes(item.name) || seen.has(item.name)) fail();
        seen.add(item.name);
        return { name: item.name, enabled: string(item.enabled, 40),
          defaultInboundAction: string(item.defaultInboundAction, 40), defaultOutboundAction: string(item.defaultOutboundAction, 40) };
      }) };
    }
    result.events = read('events', '건', true);
    const eventData = result.events.data;
    if (!time(eventData.windowStart) || !time(eventData.windowEnd)
      || Math.abs(Date.parse(eventData.windowEnd) - Date.parse(eventData.windowStart) - 86400000) > 1000
      || Date.parse(eventData.windowEnd) > Date.parse(value.finishedAt) + 1000) fail();
    const logs = array(eventData.logs, 2);
    if (logs.length !== 2 || new Set(logs.map(log => log?.logName)).size !== 2) fail();
    result.events.data = { windowStart: eventData.windowStart, windowEnd: eventData.windowEnd, logs: logs.map(log => {
      if (!object(log) || !['System', 'Application'].includes(log.logName)
        || !['ok', 'partial', 'error'].includes(log.status) || !time(log.checkedAt)
        || Date.parse(log.checkedAt) > Date.parse(value.finishedAt) + 1000
        || Date.parse(log.checkedAt) < Date.parse(value.startedAt) - 1000) fail();
      const safe = { logName: log.logName, status: log.status, checkedAt: log.checkedAt, error: error(log.error) };
      if (log.status === 'error') return safe;
      const warnings = number(log.warningCount, 0, 5000), errors = number(log.errorCount, 0, 5000);
      if (!Number.isInteger(warnings) || !Number.isInteger(errors) || warnings + errors > 5000
        || typeof log.truncated !== 'boolean' || log.countedLimit !== 5000
        || (log.status === 'partial') !== log.truncated) fail();
      return { ...safe, warningCount: warnings, errorCount: errors, truncated: log.truncated };
    }) };
    return result;
  }
  const el = (parent, tag, text) => {
    const item = document.createElement(tag);
    if (text !== undefined) item.textContent = text;
    if (parent) parent.appendChild(item);
    return item;
  };
  const style = (item, values) => {
    if (item.style) for (const [name, value] of Object.entries(values)) item.style[name] = value;
    return item;
  };
  const format = value => new Intl.NumberFormat('ko-KR', { maximumFractionDigits: 3 }).format(value);
  const at = value => time(value) ? new Date(value).toLocaleString('ko-KR', { timeZone: 'Asia/Seoul', hour12: false }) + ' (한국 시각)' : '확인 불가 · 수집 시각 없음';
  const resourceText = resource => resource ? resource.error.message : '수집 파일을 아직 불러오지 않았습니다.';
  const selectedDisk = snapshot => snapshot?.disks.data?.items.find(item => item.id.toUpperCase() === snapshot.disks.data.systemDrive.toUpperCase()) ?? null;
  function table(parent, title, headers) {
    const wrap = el(parent, 'div');
    style(wrap, { overflowX: 'auto', marginTop: '12px', marginBottom: '16px' });
    const item = el(wrap, 'table');
    style(item, { width: '100%', borderCollapse: 'collapse' });
    el(item, 'caption', title);
    const head = el(el(item, 'thead'), 'tr');
    for (const label of headers) {
      const cell = el(head, 'th', label);
      cell.setAttribute('scope', 'col');
      style(cell, { textAlign: 'left', padding: '8px', borderBottom: '1px solid #d9dde3' });
    }
    return el(item, 'tbody');
  }
  function row(body, values) {
    const item = el(body, 'tr');
    for (const value of values) style(el(item, 'td', value), { padding: '8px', borderBottom: '1px solid #d9dde3', overflowWrap: 'anywhere', whiteSpace: 'pre-line' });
    return item;
  }
  function card(parent, name, title, value, unit, checkedAt, note) {
    const item = el(parent, 'section');
    item.className = 'card';
    item.setAttribute('data-student-pc-card', name);
    style(item, { minWidth: '0', marginBottom: '0', padding: '12px', overflowWrap: 'anywhere' });
    el(item, 'h4', title);
    style(el(item, 'p', value), { fontSize: '1.15rem', fontWeight: '700', margin: '8px 0' });
    el(item, 'p', '단위: ' + unit).className = 'muted';
    el(item, 'p', '수집·확인 시각: ' + at(checkedAt)).className = 'muted';
    el(item, 'p', note).className = 'muted';
  }
  function sdp(context) {
    const resources = [context.devices, context.sessions];
    const isDemo = context.mode === 'demo' || resources.some(resource => resource?.mode === 'demo');
    const connected = !isDemo && resources.every(resource => resource?.status === 'ok' && resource.mode === 'connected');
    const disconnected = !isDemo && (context.mode === 'disconnected' || resources.some(resource => resource?.mode === 'disconnected'));
    const data = context.diagnostics?.status === 'ok' ? context.diagnostics.data : null;
    return {
      label: isDemo ? 'SDP 미연결 · 예제 모드' : connected ? '연결 자료 수신(제공 엔진)' : disconnected ? 'SDP 미연결' : 'SDP 연결 확인 불가',
      checkedAt: data?.engine?.mode === (connected ? 'connected' : disconnected ? 'disconnected' : 'demo') ? data?.checkedAt : null,
      note: connected ? '제공 기기·세션 응답의 연결 상태입니다. PC 조회와 별도입니다.' : 'PC 조회 성공과 SDP 연결 성공은 별개입니다.',
    };
  }
  function chart(parent, history) {
    const canvas = el(parent, 'canvas');
    canvas.width = 900;
    canvas.height = 180;
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'CPU와 메모리 사용률 추이. 같은 값과 수집 시각을 아래 표에서 확인할 수 있습니다.');
    style(canvas, { width: '100%', maxWidth: '900px', height: '180px' });
    let ctx;
    try { ctx = typeof canvas.getContext === 'function' ? canvas.getContext('2d') : null; } catch { return; }
    if (!ctx) return;
    const left = 42, right = 875, top = 12, bottom = 145;
    ctx.font = '12px sans-serif';
    for (const tick of [0, 50, 100]) {
      const y = bottom - tick / 100 * (bottom - top);
      ctx.strokeStyle = '#d9dde3'; ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(right, y); ctx.stroke();
      ctx.fillStyle = '#5a6472'; ctx.fillText(tick + '%', 0, y + 4);
    }
    for (const [name, color, dash] of [['cpu', '#2357c6', []], ['memory', '#6b3fb3', [7, 4]]]) {
      ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 2; ctx.setLineDash(dash);
      let previous = null;
      history.forEach((snapshot, index) => {
        const data = snapshot[name].data;
        if (!data) { previous = null; return; }
        const point = [left + index / Math.max(1, history.length - 1) * (right - left), bottom - data.usagePercent / 100 * (bottom - top)];
        if (previous) { ctx.beginPath(); ctx.moveTo(...previous); ctx.lineTo(...point); ctx.stroke(); }
        ctx.beginPath(); ctx.arc(...point, 3, 0, Math.PI * 2); ctx.fill(); previous = point;
      });
    }
    ctx.setLineDash([]);
    ctx.fillStyle = '#5a6472'; ctx.fillText('이전 수집 → 최근 수집 (동일 간격의 표본 순서)', left, 172);
  }
  function paint(root, context) {
    root.replaceChildren();
    root.setAttribute('aria-busy', state.status === 'loading' ? 'true' : 'false');
    el(root, 'h3', '내 PC 관제 대시보드 · 학생 추가 기능');
    el(root, 'p', '1. PC 자원 비교  ·  2. 네트워크·방화벽 조회  ·  3. Windows 기록 집계');
    const controls = style(el(root, 'div'), { display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '12px' });
    const button = el(controls, 'button', '다시 조회');
    currentButton = button;
    button.type = 'button'; button.className = 'btn'; button.disabled = state.status === 'loading';
    button.setAttribute('aria-label', '다시 조회');
    const file = el(controls, 'input');
    file.type = 'file'; file.accept = '.json,application/json'; file.hidden = true;
    file.setAttribute('aria-label', 'PC 수집 JSON 파일');
    button.addEventListener('click', () => { file.value = ''; file.click(); });
    file.addEventListener('change', () => { if (file.files?.[0]) void loadFile(file.files[0]); });
    file.addEventListener('cancel', () => {
      state.notice = '파일 선택을 취소했습니다. 새 PC 조회는 실행되지 않았습니다.';
      updateCurrent();
      if (typeof currentButton?.focus === 'function') currentButton.focus();
    });
    const feedback = el(controls, 'p', state.status === 'loading' ? '수집 파일을 읽는 중입니다…' : state.notice || '일반 PowerShell에서 수집한 파일을 선택하세요.');
    feedback.setAttribute('role', state.status === 'error' ? 'alert' : 'status');
    el(root, 'p', '다시 조회는 수집 파일을 선택해 읽습니다. 새 값이 필요하면 수집 도구를 다시 실행하세요. 위쪽 다시 불러오기는 제공 자료만 갱신합니다.').className = 'muted';
    const current = state.current;
    const origin = current ? current.source.mode === 'measured' ? 'PC 실측 · 사용자 PC에서 수집한 파일' : '예시 값 · 실제 조회 결과가 아닌 설명용 값' : 'PC 측정값 없음';
    const badge = el(root, 'p', origin);
    badge.setAttribute('data-student-pc-source', current?.source.mode || 'unavailable');
    style(badge, { fontWeight: '700', color: current?.source.mode === 'example' ? '#9a5b00' : '#1c2430' });
    if (current) el(root, 'p', '파일 수집 종료: ' + at(current.finishedAt) + ' · 현재 실시간 값이 아닌 수집 시각의 스냅샷입니다.');
    const cards = style(el(root, 'div'), { display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: '12px' });
    const cpu = current?.cpu, memory = current?.memory, disks = current?.disks, disk = selectedDisk(current);
    const absentReason = state.status === 'error' ? state.notice : state.status === 'loading' ? '새 수집 파일을 읽는 중입니다.' : '수집 파일을 아직 불러오지 않았습니다.';
    card(cards, 'cpu', 'CPU 사용률', cpu?.data ? format(cpu.data.usagePercent) + '%' : '확인 불가', '%', cpu?.checkedAt,
      cpu?.data ? 'Win32_Processor.LoadPercentage 평균입니다.' : cpu ? resourceText(cpu) : absentReason);
    card(cards, 'memory', '메모리 사용량', memory?.data ? format(memory.data.usedGiB) + ' / ' + format(memory.data.totalGiB) + ' GiB · ' + format(memory.data.usagePercent) + '%' : '확인 불가',
      'GiB, %', memory?.checkedAt, memory?.data ? 'Windows 가시 물리 메모리의 사용량입니다.' : memory ? resourceText(memory) : absentReason);
    card(cards, 'disk', '디스크 여유 공간' + (disk ? ' · ' + disk.id : ''), disk?.status === 'ok' ? format(disk.freeGiB) + ' GiB' : '확인 불가',
      'GiB', disks?.checkedAt, disk?.status === 'ok' ? '전체 ' + format(disk.totalGiB) + ' GiB 중 ' + format(disk.freePercent) + '% 남음' : disk?.error?.message || (disks?.data ? '시스템 드라이브의 용량을 확인할 수 없습니다.' : disks ? resourceText(disks) : absentReason));
    const connection = sdp(context);
    card(cards, 'sdp', 'SDP 연결', connection.label, '연결 상태', connection.checkedAt, connection.note);

    const trend = style(el(root, 'section'), { marginTop: '24px' });
    el(trend, 'h4', 'PC 자원 추이와 직전 측정 비교');
    if (!current) el(trend, 'p', '현재 수집 결과가 없어 추이를 표시할 수 없습니다.');
    else {
      el(trend, 'p', '이 페이지에서 불러온 같은 PC·같은 자료 유형의 최근 20개 표본입니다. 페이지를 새로 열면 비교 기록은 초기화됩니다.');
      const previous = state.history.length > 1 ? state.history[state.history.length - 2] : null;
      const delta = (value, before, unit) => (value - before > 0 ? '+' : '') + format(value - before) + ' ' + unit;
      if (!previous) el(trend, 'p', '비교 자료 부족 · 더 나중에 수집한 같은 PC 파일을 불러오세요.');
      else {
        const oldDisk = previous.disks.data?.items.find(item => item.id === disk?.id && item.status === 'ok');
        el(trend, 'p', '비교 기준: ' + at(previous.finishedAt) + ' → ' + at(current.finishedAt));
        el(trend, 'p', 'CPU 변화: ' + (cpu.data && previous.cpu.data ? delta(cpu.data.usagePercent, previous.cpu.data.usagePercent, '%p') : '확인 불가'));
        el(trend, 'p', '메모리 사용량 변화: ' + (memory.data && previous.memory.data ? delta(memory.data.usedGiB, previous.memory.data.usedGiB, 'GiB') : '확인 불가'));
        el(trend, 'p', '동일 드라이브 여유 공간 변화: ' + (disk?.status === 'ok' && oldDisk ? delta(disk.freeGiB, oldDisk.freeGiB, 'GiB') : '확인 불가 · 같은 드라이브의 비교 자료 부족'));
      }
      el(trend, 'p', '추이: CPU 사용률(실선), 메모리 사용률(점선), 단위 %. 정확한 값과 시각은 아래 표에 함께 표시합니다.');
      chart(trend, state.history);
      const body = table(trend, '수동 수집 기록 · 항목마다 수집 시각 표시', ['수집 종료 시각', 'CPU (%)', '메모리 사용 (GiB)', '메모리 (%)', '시스템 디스크 여유 (GiB)']);
      for (const snapshot of state.history) {
        const drive = selectedDisk(snapshot);
        row(body, [at(snapshot.finishedAt), (snapshot.cpu.data ? format(snapshot.cpu.data.usagePercent) : '확인 불가') + '\n' + at(snapshot.cpu.checkedAt),
          (snapshot.memory.data ? format(snapshot.memory.data.usedGiB) : '확인 불가') + '\n' + at(snapshot.memory.checkedAt),
          (snapshot.memory.data ? format(snapshot.memory.data.usagePercent) : '확인 불가') + '\n' + at(snapshot.memory.checkedAt),
          (drive?.status === 'ok' ? drive.id + ' ' + format(drive.freeGiB) : '확인 불가') + '\n' + at(snapshot.disks.checkedAt)]);
      }
      const diskBody = table(trend, '현재 수집 파일의 고정 드라이브', ['드라이브', '남은 공간', '전체 공간', '단위', '수집 시각']);
      if (disks.data) {
        if (disks.data.items.length === 0) row(diskBody, ['없음', '조회된 고정 드라이브 없음', '—', 'GiB', at(disks.checkedAt)]);
        for (const drive of disks.data.items) row(diskBody, [drive.id, drive.status === 'ok' ? format(drive.freeGiB) : '확인 불가 · ' + drive.error.message,
          drive.status === 'ok' ? format(drive.totalGiB) : '확인 불가', 'GiB', at(disks.checkedAt)]);
      } else row(diskBody, ['확인 불가', resourceText(disks), '확인 불가', 'GiB', at(disks.checkedAt)]);
    }
    const settings = style(el(root, 'section'), { marginTop: '24px' });
    el(settings, 'h4', '네트워크·방화벽 조회');
    el(settings, 'p', '읽기 전용 조회입니다. IP·방화벽·보안 설정을 변경하지 않습니다.');
    if (!current) el(settings, 'p', '확인 불가 · ' + absentReason);
    else {
      const network = current.network, firewall = current.firewall;
      const networkBody = table(settings, '로컬 네트워크 구성', ['인터페이스', '항목', '값', '단위', '수집 시각']);
      if (!network.data) row(networkBody, ['확인 불가', '네트워크', resourceText(network), '주소, 상태', at(network.checkedAt)]);
      else {
        if (network.data.items.length === 0) row(networkBody, ['없음', '네트워크', '조회된 인터페이스 없음', '상태', at(network.checkedAt)]);
        for (const item of network.data.items) for (const [name, key] of [['IPv4', 'ipv4'], ['IPv6', 'ipv6'], ['게이트웨이', 'gateway'], ['DNS', 'dns']]) {
          row(networkBody, [item.label, name, item[key].length ? item[key].join(', ') : '설정된 주소 없음', '주소', at(network.checkedAt)]);
        }
        if (network.data.truncated) el(settings, 'p', '일부 조회 · 인터페이스 32개까지만 표시합니다.');
      }
      const firewallBody = table(settings, 'Windows 방화벽 프로필별 적용 설정', ['프로필', '사용 여부', '기본 인바운드', '기본 아웃바운드', '수집 시각']);
      const enabled = { True: '사용(True)', False: '사용 안 함(False)', NotConfigured: '설정 확인 불가(NotConfigured)' };
      const action = { Allow: '허용(Allow)', Block: '차단(Block)', NotConfigured: '설정 확인 불가(NotConfigured)' };
      if (!firewall.data) row(firewallBody, ['확인 불가', resourceText(firewall), '확인 불가', '확인 불가', at(firewall.checkedAt)]);
      else {
        if (firewall.data.items.length === 0) row(firewallBody, ['없음', '조회된 프로필 없음', '확인 불가', '확인 불가', at(firewall.checkedAt)]);
        for (const item of firewall.data.items) row(firewallBody, [item.name, enabled[item.enabled] || '확인 불가', action[item.defaultInboundAction] || '확인 불가',
          action[item.defaultOutboundAction] || '확인 불가', at(firewall.checkedAt)]);
      }
      el(settings, 'p', '방화벽 값의 단위는 설정 상태입니다. 프로필 설정 조회이며 모든 규칙의 효과나 통신 안전성을 검사한 결과는 아닙니다.').className = 'muted';
    }
    const events = style(el(root, 'section'), { marginTop: '24px' });
    el(events, 'h4', '최근 Windows 기록 · System / Application');
    el(events, 'p', '이 경고·오류 건수는 Windows 기록 집계이며 침해나 공격 탐지 결과가 아닙니다.');
    if (!current) el(events, 'p', '확인 불가 · ' + absentReason);
    else {
      const resource = current.events;
      el(events, 'p', '조회 구간: ' + at(resource.data.windowStart) + ' ~ ' + at(resource.data.windowEnd) + ' · 최근 24시간');
      const body = table(events, 'Windows 경고·오류 집계', ['로그', '경고', '오류', '단위', '집계 상태', '수집 시각']);
      for (const log of resource.data.logs) {
        const prefix = log.truncated ? '최소 ' : '';
        row(body, [log.logName, log.status === 'error' ? '확인 불가' : prefix + format(log.warningCount),
          log.status === 'error' ? '확인 불가' : prefix + format(log.errorCount), '건',
          log.status === 'error' ? log.error.message : log.truncated ? '일부 집계 · 최근 5,000건만 집계' : '해당 구간 집계', at(log.checkedAt)]);
      }
      el(events, 'p', '0건은 해당 구간을 조회했지만 일치하는 기록이 없다는 뜻입니다. 접근 거부·조회 실패는 확인 불가로 구분합니다.').className = 'muted';
    }
  }
  async function loadFile(file) {
    const id = ++state.loadId;
    state.status = 'loading'; state.current = null; state.notice = '';
    updateCurrent();
    let timer;
    try {
      if (!file || typeof file.text !== 'function' || typeof file.size !== 'number' || file.size > 262144) fail();
      const text = await Promise.race([
        file.text(),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('READ_TIMEOUT')), 10000); }),
      ]);
      if (id !== state.loadId) return;
      let value;
      try { value = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { fail(); }
      const snapshot = normalise(value);
      const last = state.history[state.history.length - 1];
      const sameSource = last && last.source.mode === snapshot.source.mode && last.source.computerId === snapshot.source.computerId;
      if (sameSource && Date.parse(snapshot.finishedAt) < Date.parse(last.finishedAt)) throw new Error('OLD_FILE');
      if (!sameSource) state.history = [];
      const duplicate = sameSource && Date.parse(snapshot.finishedAt) === Date.parse(last.finishedAt);
      if (!duplicate) state.history = [...state.history, snapshot].slice(-20);
      state.current = duplicate ? last : snapshot;
      state.status = 'ok';
      state.notice = duplicate ? '동일 수집 시각의 파일입니다. 새 측정값이 추가된 것은 아닙니다.' : '수집 파일을 읽었습니다. 항목별 시각·실패 여부를 확인하세요.';
      if (last && !sameSource) state.notice += ' PC 또는 실측/예시 구분이 달라 비교 기록을 초기화했습니다.';
    } catch (cause) {
      if (id !== state.loadId) return;
      const code = Object.hasOwn(errors, cause?.message) ? cause.message : 'READ_FAILED';
      state.current = null; state.status = 'error'; state.notice = 'PC 조회 결과 확인 불가: ' + errors[code];
    } finally {
      clearTimeout(timer);
      if (id === state.loadId) {
        updateCurrent();
        if (typeof currentButton?.focus === 'function') currentButton.focus();
      }
    }
  }
  return {
    render(context) {
      const root = document.createElement('section');
      root.setAttribute('data-student-pc-dashboard', 'true');
      updateCurrent = () => paint(root, context);
      updateCurrent();
      return root;
    },
  };
}

export function createStudentView() {
  const pcDashboard = createPcDashboard();
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
      root.appendChild(pcDashboard.render({ devices, sessions, diagnostics, mode }));
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
    renderVulnerabilities({ status, mode, data, error }) {
      const root = document.createElement('section');
      const isText = value => typeof value === 'string' && value.trim() !== '';
      const shown = value => isText(value) ? value : '확인 불가';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const showField = (parent, label, value) => {
        if (isText(value) || typeof value === 'number' && Number.isFinite(value)) appendText(parent, 'p', `${label}: ${value}`);
      };
      const modes = { demo: '예제 모드(demo)', disconnected: '연결 없음(disconnected)', unknown: '연결 상태 확인 불가(unknown)' };
      if (isText(mode) && Object.hasOwn(modes, mode)) appendText(root, 'p', modes[mode]);
      appendText(root, 'p', 'OSV는 알려진 취약점 데이터베이스입니다. 조회 결과만으로 패키지나 앱 전체의 안전을 보장할 수 없습니다.');
      const retryGuide = '조회하려면 제공 화면의 설치 패키지 조회 버튼을 직접 누르세요.';
      if (status === 'idle') {
        appendText(root, 'h3', '패키지 조회 전(idle)');
        appendText(root, 'p', retryGuide);
        return root;
      }
      if (status === 'loading') {
        appendText(root, 'h3', '패키지 조회 중(loading)');
        appendText(root, 'p', '중단하려면 제공 화면의 패키지 조회 취소 버튼을 직접 누르세요.');
        return root;
      }
      if (status === 'error') {
        appendText(root, 'h3', '패키지 조회 실패(error)');
        appendText(root, 'p', `조회 실패: ${shown(error?.message)}`);
        showField(root, '오류 코드', error?.code);
        if (isText(error?.code) && error.code.includes('TIMEOUT')) appendText(root, 'p', '시간 초과로 조회를 마치지 못했습니다.');
        if (error?.code === 'CANCELLED' || error?.code === 'REQUEST_CANCELLED') appendText(root, 'p', '조회가 취소됐습니다. 이전 결과는 현재 조회 결과가 아닙니다.');
        appendText(root, 'p', retryGuide);
        return root;
      }
      const scanStates = {
        complete: '모두 조회(complete)', partial: '일부 조회 실패(partial)', not_checked: '아직 조회 안 함(not_checked)',
        not_configured: '조회 준비 미완료(not_configured)', unverifiable: 'lock 파일 확인 불가(unverifiable)',
      };
      if (status !== 'ok' || !isText(data?.status) || !Object.hasOwn(scanStates, data.status)) {
        appendText(root, 'h3', '패키지 조회 결과 확인 불가');
        appendText(root, 'p', retryGuide);
        return root;
      }
      appendText(root, 'h3', scanStates[data.status]);
      showField(root, 'lockfileVersion', data.lockfileVersion);
      showField(root, 'lockfileHash', data.lockfileHash);
      showField(root, '전체 확인 시각(checkedAt)', data.checkedAt);
      if (data.status === 'not_configured') {
        appendText(root, 'p', '조회 대상 프로젝트 설정이 필요합니다. 담당자에게 대상 프로젝트와 공개 조회 승인 목록을 확인해 달라고 요청하세요.');
        return root;
      }
      if (data.status === 'not_checked') {
        appendText(root, 'p', '승인된 공개 조회 대상이 없어 아직 조회하지 않았습니다. 담당자에게 공개 조회 승인 목록을 확인해 달라고 요청하세요.');
        return root;
      }
      if (data.status === 'unverifiable') {
        appendText(root, 'p', 'lock 파일을 확인할 수 없어 조회 결과를 판단할 수 없습니다. 담당자에게 lock 파일과 설치 메타데이터 확인을 요청하세요.');
        return root;
      }
      if (data.status === 'partial') appendText(root, 'p', '일부 조회를 마치지 못했습니다. 이미 받은 취약점 ID와 확인된 패키지별 결과를 표시합니다.');
      if (!Array.isArray(data.packages)) {
        appendText(root, 'p', '패키지 결과 목록을 확인할 수 없습니다.');
        return root;
      }
      if (data.packages.length === 0) {
        appendText(root, 'p', '표시할 패키지 결과가 없습니다.');
        return root;
      }
      const exactVersion = value => {
        if (typeof value !== 'string') return false;
        const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(value);
        return !!match && (match[4] === undefined || match[4].split('.').every(part => !/^0\d+$/.test(part)));
      };
      const packageStates = { known_vulnerabilities: '알려진 항목 있음', none_found: '알려진 항목 없음', unverifiable: '조회 확인 불가' };
      const list = document.createElement('ul');
      for (const pkg of data.packages) {
        const row = document.createElement('li');
        if (isText(pkg?.name)) row.setAttribute('data-student-package-name', pkg.name);
        const versionIsExact = exactVersion(pkg?.version);
        if (versionIsExact) row.setAttribute('data-student-package-version', pkg.version);
        appendText(row, 'p', `패키지 이름(name): ${shown(pkg?.name)}`);
        appendText(row, 'p', `버전(version): ${shown(pkg?.version)}`);
        if (!versionIsExact) appendText(row, 'p', '정확한 설치 버전 확인 불가. 버전 범위나 태그를 설치 버전으로 사용하지 않습니다.');
        const findings = Array.isArray(pkg?.vulnerabilities) ? pkg.vulnerabilities : null;
        let packageStatus = isText(pkg?.status) && Object.hasOwn(packageStates, pkg.status) ? pkg.status : 'unverifiable';
        if (!versionIsExact || !findings || packageStatus === 'none_found' && findings.length > 0
          || packageStatus === 'known_vulnerabilities' && findings.length === 0) packageStatus = 'unverifiable';
        appendText(row, 'p', `조회 상태: ${packageStates[packageStatus]}(${packageStatus})`);
        appendText(row, 'p', `출처(source): ${shown(pkg?.source)}`);
        appendText(row, 'p', `패키지 확인 시각(checkedAt): ${shown(pkg?.checkedAt)}`);
        if (packageStatus === 'none_found') appendText(row, 'p', '이 버전의 조회 범위에서 알려진 항목이 없습니다. 패키지나 앱 전체가 안전하다는 보장은 아닙니다.');
        if (packageStatus === 'unverifiable') appendText(row, 'p', findings?.length > 0
          ? '일부 확인·전체 조회 확인 불가. 아래 취약점 ID는 이미 받은 일부 결과입니다.'
          : '전체 조회 결과를 확인할 수 없습니다. 조회 실패는 알려진 항목이 없다는 뜻이 아닙니다.');
        if (findings?.length > 0) {
          const findingList = document.createElement('ul');
          for (const finding of findings) appendText(findingList, 'li', `취약점 ID: ${shown(finding?.id)} · 수정 시각(modified): ${shown(finding?.modified)}`);
          row.appendChild(findingList);
        }
        list.appendChild(row);
      }
      root.appendChild(list);
      return root;
    },
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
    renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error }) {
      const root = document.createElement('section');
      const isText = value => typeof value === 'string' && value.trim() !== '';
      const appendText = (parent, tag, text) => {
        const element = document.createElement(tag);
        element.textContent = text;
        parent.appendChild(element);
        return element;
      };
      const showField = (label, value) => {
        if (isText(value) || typeof value === 'number' && Number.isFinite(value)) appendText(root, 'p', `${label}: ${value}`);
      };
      const labels = {
        idle: '아직 미실행(idle)',
        loading: '조치 준비 또는 결과 조회 중(loading)',
        prepared: '준비됨·미실행(prepared)',
        executing: '서버에 전달 중(executing)',
        pending: '서버 접수·처리 중(pending)',
        succeeded: '효과 확인(succeeded)',
        denied: '거절(denied)',
        failed: '실패(failed)',
        unknown: '결과 불명(unknown)',
        expired: '확인 기한 지남(expired)',
        error: '요청 처리 안 됨(error)',
      };
      const mismatch = isText(event?.id) && isText(receipt?.eventId) && event.id !== receipt.eventId
        || isText(actionId) && isText(receipt?.actionId) && actionId !== receipt.actionId;
      let currentStatus = isText(status) && Object.hasOwn(labels, status) ? status : 'unknown';
      if (currentStatus === 'succeeded' && observation?.effectApplied !== true || mismatch || receipt?.superseded === true) currentStatus = 'unknown';
      appendText(root, 'h3', labels[currentStatus]);
      if (currentStatus !== status) showField('전달된 상태(status)', status);
      const resultGuide = '같은 조치를 다시 집행하지 말고 제공 화면의 원천 결과만 재조회 버튼으로 기존 요청의 결과만 직접 확인하세요.';
      if (currentStatus === 'idle') {
        appendText(root, 'p', 'AI 조치 제안만으로는 실행되지 않습니다.');
        showField('안내(message)', message);
      } else if (currentStatus === 'loading') {
        appendText(root, 'p', '조치를 준비하거나 연동 시스템의 결과를 조회하고 있습니다. 현재 요청의 결과는 아직 확인되지 않았습니다.');
      } else if (currentStatus === 'prepared') {
        appendText(root, 'p', '조치는 준비만 됐으며 아직 실행되지 않았습니다. 사건·근거·조치·실제 대상과 확인 기한을 읽고 사람 확인을 해야 합니다.');
        appendText(root, 'p', '집행하려면 제공 화면의 대상과 조치를 확인했으며 집행합니다 버튼을 사용합니다.');
      } else if (currentStatus === 'executing') {
        appendText(root, 'p', '서버에 요청을 전달하고 있습니다. 실제 처리 결과와 효과는 아직 확인되지 않았습니다.');
      } else if (currentStatus === 'pending') {
        appendText(root, 'p', '서버가 요청을 받아 처리 중입니다. 접수 응답(ACK)은 실제 효과 확인이 아닙니다. 결과는 아직 확인되지 않았습니다.');
      } else if (currentStatus === 'succeeded') {
        appendText(root, 'p', '연동 시스템이 관측한 실제 효과를 확인했습니다.');
        showField('관측 시각(observation.observedAt)', observation.observedAt);
        appendText(root, 'p', 'effectApplied: true');
      } else if (currentStatus === 'denied' || currentStatus === 'failed') {
        if (isText(message)) showField('안내(message)', message);
        else appendText(root, 'p', '추가 사유가 전달되지 않았습니다.');
      } else if (currentStatus === 'unknown') {
        appendText(root, 'p', '실제 효과를 확인할 수 없습니다. 성공이나 효과 없음으로 판단하지 마세요.');
        if (mismatch) appendText(root, 'p', '영수증의 사건 또는 조치가 현재 요청과 맞지 않습니다.');
        if (receipt?.superseded === true) appendText(root, 'p', '이전 조회는 최신 결과를 대신하지 않습니다(superseded).');
        appendText(root, 'p', resultGuide);
      } else if (currentStatus === 'expired') {
        appendText(root, 'p', '사람 확인 기한이 지났습니다. 제공 화면에서 현재 기록의 조치를 다시 준비하고 대상과 기한을 확인하세요.');
      } else if (currentStatus === 'error') {
        appendText(root, 'p', '요청이 처리되지 않았습니다. 안전한 오류 내용을 확인하세요.');
      }
      if (['error', 'unknown', 'expired', 'denied', 'failed'].includes(currentStatus)) {
        showField('오류 코드(error.code)', error?.code);
        showField('오류 내용(error.message)', error?.message);
      }
      showField('사건 ID(event.id)', event?.id);
      if (Array.isArray(event?.evidence)) {
        const evidenceList = document.createElement('ul');
        for (const evidence of event.evidence) {
          if (isText(evidence?.id)) appendText(evidenceList, 'li', `근거 ID: ${evidence.id}`);
        }
        root.appendChild(evidenceList);
      }
      showField('조치 ID(actionId)', actionId);
      showField('실제 대상 ID(target.id)', target?.id);
      showField('대상 세대(target.generation)', target?.generation);
      showField('요청 ID(receipt.requestId)', receipt?.requestId);
      showField('영수증 ID(receipt.receiptId)', receipt?.receiptId);
      showField('결과 버전(receipt.version)', receipt?.version);
      if (currentStatus === 'prepared' || currentStatus === 'expired') showField('사람 확인 기한(confirmationExpiresAt)', confirmationExpiresAt);
      if (receipt?.replayed === true) {
        appendText(root, 'p', '같은 요청의 재응답(replayed: true)입니다. 새 요청을 중복 전송하지 말고 기존 요청 ID로 결과만 확인하세요.');
      }
      if (!mismatch) {
        if (isText(event?.id)) root.setAttribute('data-student-action-event', event.id);
        if (isText(receipt?.requestId)) root.setAttribute('data-student-action-request', receipt.requestId);
      }
      appendText(root, 'p', '연동 시스템이 지원하는 조치가 없는 기록에 조치 준비 버튼이 없는 것은 정상입니다.');
      appendText(root, 'p', '조치 화면 취소는 이미 서버에 전달된 조치 효과를 되돌리는 기능이 아닙니다.');
      return root;
    },
  };
}
