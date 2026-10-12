// Standalone, deterministic decision module: no imports, I/O, network, clock, or retained event state.
// Keep these constants identical to patterns.json. Numeric thresholds are local policy, not MITRE standards.
const PATTERNS = [
  {
    "name": "repeated_login_failures",
    "technique": "T1110.001",
    "condition": "출발 주소와 계정이 식별되는 인증 실패 요약에서 짧은 시간의 많은 실패 또는 강하게 상관된 반복 실패를 찾는다. 낮은 횟수는 알림만 남긴다.",
    "thresholds": { "blockCount": 30, "alertCount": 3, "minRuleLevel": 10, "maxWindowSeconds": 300 },
    "evidence": "MITRE T1110.001은 비밀번호 추측과 반복 인증 실패를 설명한다. 횟수·시간·수준의 수치는 이 학습용 보수적 정책이며 MITRE가 지정한 값이 아니다.",
    "source": "https://attack.mitre.org/techniques/T1110/001/"
  },
  {
    "name": "password_spraying",
    "technique": "T1110.003",
    "condition": "동일 출발 주소의 실패 경보가 여러 계정에 같은 비밀번호를 대입했다고 명시하고, 서로 다른 계정이 기준 이상인 경우를 찾는다. 비밀번호 원문은 읽지 않는다.",
    "thresholds": { "blockAccounts": 5, "minRuleLevel": 10, "maxWindowSeconds": 300 },
    "evidence": "MITRE T1110.003은 여러 계정에 한 비밀번호 또는 소수 비밀번호를 시도하는 password spraying을 설명한다. 계정 수 기준은 학습용 정책이다.",
    "source": "https://attack.mitre.org/techniques/T1110/003/"
  },
  {
    "name": "multi_account_failures",
    "technique": "T1110",
    "condition": "같은 주소에서 많은 계정을 바꿔 가며 인증 실패가 반복되고 자동화 정황까지 확인된 경우를 찾는다. 비밀번호가 같다는 증거가 없으면 스프레이로 단정하지 않는다.",
    "thresholds": { "blockAccounts": 15, "minRuleLevel": 10, "maxWindowSeconds": 300 },
    "evidence": "MITRE T1110의 탐지는 사용자 집합을 대상으로 한 짧은 간격의 반복 인증 실패를 다룬다. 계정 수 기준은 학습용 정책이다.",
    "source": "https://attack.mitre.org/techniques/T1110/"
  }
];

function result(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}

function count(value) {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^\d{1,7}$/u.test(value))) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 0 && n <= 1000000 ? n : null;
}

function validIp(value) {
  if (typeof value !== 'string' || value.length > 45) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) {
    return value.split('.').every(x => Number(x) <= 255 && (x === '0' || !x.startsWith('0')));
  }
  if (!/^[a-f0-9:]+$/iu.test(value) || !value.includes(':') || value.includes(':::')) return false;
  const pieces = value.split('::');
  if (pieces.length > 2) return false;
  const groups = value.split(':').filter(Boolean);
  return (pieces.length === 2 || (!value.startsWith(':') && !value.endsWith(':')))
    && groups.every(x => /^[a-f0-9]{1,4}$/iu.test(x))
    && (pieces.length === 2 ? groups.length < 8 : groups.length === 8);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0, '패턴 미충족: 경보 형식 부족');
  const rule = alert.rule && typeof alert.rule === 'object' ? alert.rule : {};
  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = typeof rule.description === 'string' ? rule.description.slice(0, 2048) : '';
  const level = count(rule.level);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = mitre.slice(0, 32).some(id => typeof id === 'string' && /^T1110(?:\.00[1-4])?$/u.test(id));
  const describedSpray = /(?:같은|동일)\s*비밀번호/iu.test(description)
    && /여러\s*계정|다른\s*계정|계정\s*\d+\s*개/iu.test(description)
    && /연속|이어|실패|대입|시도/iu.test(description);
  const failure = describedSpray || /실패|failed\s+(?:login|logon|authentication|password)|authentication\s+fail|invalid\s+(?:password|user)|password\s+(?:guess|spray)|brute[ -]?force/iu.test(description);
  const authEvidence = tagged || /로그인|인증|비밀번호|계정|login|logon|authentication|password|account|brute[ -]?force/iu.test(description);
  if (!failure || !authEvidence) return result(0.1, '패턴 미충족: 정상 관찰 또는 인증 실패 증거 없음');

  const repeated = PATTERNS[0];
  const spray = PATTERNS[1];
  const multi = PATTERNS[2];
  const numericCount = count(data.count);
  const describedCount = count(description.match(/(?:실패(?:가)?\s*|failures?\s*[:=]?\s*)(\d+)\s*(?:건|times|attempts)?/iu)?.[1]);
  const failures = numericCount ?? describedCount ?? 0;
  const countConflict = numericCount !== null && describedCount !== null && numericCount !== describedCount;
  const list = Array.isArray(data.accounts) ? data.accounts.slice(0, 1000)
    : typeof data.accounts === 'string' ? data.accounts.slice(0, 4096).split(',') : [];
  const distinctAccounts = new Set(list.filter(v => typeof v === 'string' && v.trim()).map(v => v.trim())).size;
  const describedAccounts = count(description.match(/(?:계정\s*(\d+)\s*개|(?:서로\s*)?다른\s*계정\s*(\d+)\s*개|accounts?\s*[:=]?\s*(\d+))/iu)?.slice(1).find(Boolean));
  const accounts = distinctAccounts || describedAccounts || 0;
  const accountConflict = distinctAccounts > 0 && describedAccounts !== null && distinctAccounts !== describedAccounts;
  const timeMatch = description.match(/(\d+)\s*(초|분|시간|일|seconds?|minutes?|hours?|days?)/iu);
  const duration = timeMatch ? Number(timeMatch[1]) * (/^(초|seconds?)$/iu.test(timeMatch[2]) ? 1
    : /^(분|minutes?)$/iu.test(timeMatch[2]) ? 60 : /^(시간|hours?)$/iu.test(timeMatch[2]) ? 3600 : 86400) : null;
  const shortWindow = duration === null || (duration > 0 && duration <= repeated.thresholds.maxWindowSeconds);
  const source = validIp(data.srcip);
  const account = typeof data.srcuser === 'string' && data.srcuser.trim().length > 0 && data.srcuser.length <= 160;
  const correlation = source && account && tagged && Number.isInteger(level) && level >= repeated.thresholds.minRuleLevel
    && level <= 16 && shortWindow && !countConflict && !accountConflict;
  const samePassword = /같은\s*비밀번호|동일\s*비밀번호|same\s+password|password\s+spray/iu.test(description);
  const automation = /연속|이어|반복|간격|바꿔\s*가며|한\s*글자|쌓|없습니다|consecutive|repeat|interval|automated|brute[ -]?force/iu.test(description);

  if (correlation && samePassword && accounts >= spray.thresholds.blockAccounts) {
    return result(0.96, `${spray.name}: 여러 계정의 동일 비밀번호 대입 실패`);
  }
  if (correlation && failures >= repeated.thresholds.blockCount) {
    // With no duration, require an already correlated high-level T1110 summary; never accumulate singleton alerts here.
    return result(duration === null ? 0.9 : 0.96, `${repeated.name}: 상관된 다수 인증 실패`);
  }
  if (correlation && accounts >= multi.thresholds.blockAccounts && automation) {
    return result(0.9, `${multi.name}: 많은 계정을 바꾸며 반복된 인증 실패`);
  }
  if (failures >= repeated.thresholds.alertCount || (samePassword && accounts >= 2) || (tagged && level >= 5)) {
    const name = samePassword && accounts >= 2 ? spray.name : repeated.name;
    return result(failures >= 8 || samePassword ? 0.7 : 0.55, `${name}: 의심 신호, 자동 차단 근거 부족`);
  }
  return result(0.2, '패턴 미충족: 적은 인증 실패, 기록만 유지');
}
