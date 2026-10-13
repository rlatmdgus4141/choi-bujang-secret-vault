// Standalone privilege assessment. No imports, I/O, remote lookup or retained event state.
const PATTERNS = [
  {
    "name": "unexpected_admin_group_change",
    "technique": "T1098.007",
    "relatedTechniques": [
      "T1078"
    ],
    "condition": "관리자 그룹 추가가 낯선/원격 접속, 직후 관리자 명령 또는 같은 주소의 여러 계정 승격과 겹치는지 확인한다. 일반 과제 그룹 추가만으로는 차단하지 않는다.",
    "evidence": "MITRE T1098.007은 계정을 추가 로컬/도메인 그룹에 넣어 높은 권한과 접근을 확보하는 계정 조작을 설명하며 T1078은 정상 계정 악용을 다룬다.",
    "source": "https://attack.mitre.org/techniques/T1098/007/"
  },
  {
    "name": "abnormal_elevated_session",
    "technique": "T1068",
    "relatedTechniques": [
      "T1078"
    ],
    "condition": "새 관리자 권한/세션 변경 직후 권한 명령을 쓰거나 낯선 접속에서 세션이 승격되는 경우, 다른 계정 권한으로 관리자 명령을 실행하는 경우를 확인한다. 단순 관리자 명령 하나는 알림만 남긴다.",
    "evidence": "T1068은 취약점 악용을 통한 권한 상승을 다룬다. 이 모듈은 상승/사용의 상관 신호를 탐지하며 관리자 명령만으로 취약점 악용 성공을 단정하지 않는다.",
    "source": "https://attack.mitre.org/techniques/T1068/"
  },
  {
    "name": "off_hours_privileged_execution",
    "technique": "T1078",
    "relatedTechniques": [
      "T1068"
    ],
    "condition": "평소 시간 밖에 낯선 접속 맥락에서 관리자 명령이 실행되는 복합 신호를 확인한다. 시각 하나 또는 출발 주소 하나만으로 차단하지 않는다.",
    "evidence": "T1078의 계정 악용 탐지는 정상 계정의 평소와 다른 활동을 살핀다. 시간과 접속/권한 사용의 결합은 이 과제의 상관 정책이다.",
    "source": "https://attack.mitre.org/techniques/T1078/"
  },
  {
    "name": "rapid_admin_privilege_reinstatement",
    "technique": "T1098.007",
    "relatedTechniques": [
      "T1078"
    ],
    "condition": "관리자 그룹에서 제거된 계정이 5분 안에 다시 그룹에 들어가는 명확한 재승격 요약을 확인한다. 긴 시간 후 승인된 변경이나 숫자 불일치는 자동 차단하지 않는다.",
    "evidence": "T1098.007의 그룹 조작을 바탕으로 제거 뒤 즉시 재추가되는 변경을 상관 분석한다. 5분 기준은 학습 정책이며 MITRE의 고정 수치가 아니다.",
    "source": "https://attack.mitre.org/techniques/T1098/007/"
  }
];

function result(confidence, pattern, detail) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: `${pattern}: ${detail}` };
}
function text(value, limit = 4096) { return typeof value === 'string' ? value.slice(0, limit) : ''; }
function number(value) {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^\d{1,7}$/u.test(value))) return null;
  const n = Number(value); return Number.isSafeInteger(n) && n >= 0 && n <= 1000000 ? n : null;
}
function validIp(value) {
  if (typeof value !== 'string' || value.length > 45) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) return value.split('.').every(x => Number(x) <= 255 && (x === '0' || !x.startsWith('0')));
  if (!/^[a-f0-9:]+$/iu.test(value) || !value.includes(':') || value.includes(':::')) return false;
  const parts = value.split('::'), groups = value.split(':').filter(Boolean);
  return parts.length <= 2 && (parts.length === 2 || (!value.startsWith(':') && !value.endsWith(':')))
    && groups.every(x => /^[a-f0-9]{1,4}$/iu.test(x)) && (parts.length === 2 ? groups.length < 8 : groups.length === 8);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0, 'no_match', '경보 형식 부족');
  const rule = alert.rule && typeof alert.rule === 'object' && !Array.isArray(alert.rule) ? alert.rule : {};
  const data = alert.data && typeof alert.data === 'object' && !Array.isArray(alert.data) ? alert.data : {};
  const description = text(rule.description);
  const group = text(data.group, 160).trim().toLowerCase();
  const tags = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = prefix => tags.slice(0, 32).some(tag => typeof tag === 'string' && (tag === prefix || tag.startsWith(prefix + '.')));
  const groupTagged = tagged('T1078') || tagged('T1098');
  const related = groupTagged || tagged('T1068');
  const level = number(rule.level);
  const hasAccount = typeof data.srcuser === 'string' && data.srcuser.trim().length > 0 && data.srcuser.length <= 160;
  const failed = /취소|실패|거부|cancel(?:led|ed)?|\bfailed\b|\bdenied\b/iu.test(description);
  const approved = /승인된|승인된\s*변경|\bapproved\s+(?:change|promotion|administrative)/iu.test(description);
  const noCommand = /명령(?:은|이)?\s*없|no\s+(?:admin(?:istrator)?\s+)?command/iu.test(description);
  const explicitAdminCommand = !noCommand && /관리자\s*명령|권한\s*명령|admin(?:istrator)?\s+command|privileged\s+(?:command|execution)/iu.test(description);
  const groupInDescription = /관리자\s*그룹|admin(?:istrators?|istrative)?\s+group|domain\s+admins/iu.test(description);
  const nonAdmin = /관리자\s*그룹.{0,10}(?:아닙|아니|아님)|not\s+(?:an?\s+)?admin(?:istrator)?\s+group/iu.test(description);
  const adminGroup = !nonAdmin && (group ? ['administrators','domain admins','enterprise admins','sudo','wheel','관리자'].includes(group) : groupInDescription);
  const added = adminGroup && /추가|들어가|들어왔|들어오|\badded\b|\bjoined\b|\bre-?added\b/iu.test(description);
  const unfamiliar = /처음\s*보|처음\s*봅|처음\s*봤|낯선|처음\s*봅니다|unfamiliar|unseen|first[- ]seen|new\s+(?:address|source|network)/iu.test(description);
  const remote = /원격\s*주소|remote\s+(?:address|source|network)/iu.test(description);
  const offHours = /시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|업무\s*시간\s*외|outside\s+(?:normal|business|usual)\s+hours|off[- ]hours/iu.test(description);
  const adminCommand = explicitAdminCommand || !noCommand && groupInDescription && offHours
    && /명령.{0,12}실행|command\s+execution/iu.test(description)
    && !/일반\s*명령|normal\s+command/iu.test(description);
  const elevation = /방금\s*관리자|관리자\s*권한.{0,15}바뀌|새(?:로)?\s*관리자|newly\s+(?:elevated|admin)|just\s+(?:became|promoted)|session.{0,30}(?:elevated|became.{0,10}admin|changed.{0,10}admin)/iu.test(description);
  const otherIdentity = /다른\s*계정.{0,10}권한|another\s+(?:account|user).{0,15}(?:privilege|credential)|other\s+account.{0,15}(?:privilege|credential)/iu.test(description);
  const rawCount = number(data.count);
  const describedCount = number(description.match(/(\d{1,7})\s*(?:개|건|번|accounts?|events|times)/iu)?.[1]);
  const conflicting = rawCount !== null && describedCount !== null && rawCount !== describedCount;
  const attempts = rawCount ?? describedCount ?? 0;
  const multipleAccounts = /계정\s*\d{1,7}\s*개|multiple\s+accounts|\d{1,7}\s+accounts/iu.test(description);
  const sameSource = /같은\s*주소|same\s+(?:source|address|ip)/iu.test(description);
  const removed = /그룹에서\s*빠진|제거|removed|revoked/iu.test(description);
  const again = /다시|재추가|re-?added|again/iu.test(description);
  const time = description.match(/(\d+)\s*(초|분|시간|일|seconds?|minutes?|hours?|days?)/iu);
  const seconds = time ? Number(time[1]) * (/^(초|seconds?)$/iu.test(time[2]) ? 1 : /^(분|minutes?)$/iu.test(time[2]) ? 60 : /^(시간|hours?)$/iu.test(time[2]) ? 3600 : 86400) : null;
  const groupMalformed = data.group !== undefined && (typeof data.group !== 'string' || !data.group.trim());
  const demoted = /권한.{0,15}(?:낮아|회수|해제)|demot(?:ed|ion)|downgrad|privileges?.{0,15}(?:removed|reduced)/iu.test(description);
  const strong = related && level !== null && level >= 10 && level <= 16 && validIp(data.srcip)
    && hasAccount && !failed && !approved && !conflicting && !groupMalformed;
  if (strong && groupTagged && added && (remote || unfamiliar || adminCommand || sameSource && multipleAccounts && attempts >= 3)) {
    return result(0.96, PATTERNS[0].name, '관리자 그룹 변경과 비정상 접속/권한 사용이 겹침');
  }
  if (strong && !demoted && (elevation && (adminCommand || unfamiliar) || otherIdentity && adminCommand)) {
    return result(0.95, PATTERNS[1].name, '권한 변경 또는 타 계정 권한 사용 근거 확인');
  }
  if (strong && adminCommand && offHours && (unfamiliar || added)) {
    return result(0.94, PATTERNS[2].name, '평소 시간 밖 비정상 권한 명령');
  }
  if (strong && groupTagged && adminGroup && removed && again && added && seconds !== null && seconds > 0 && seconds <= 300 && attempts >= 2) {
    return result(0.92, PATTERNS[3].name, '제거 직후 관리자 권한 재추가');
  }
  if (related && level !== null && level >= 5 && level <= 16) {
    return result(0.65, 'privilege_review', '권한 의심 신호, 명확한 회수 근거 부족');
  }
  return result(0.1, 'no_match', '비정상 권한 상승 근거 없음');
}
