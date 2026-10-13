// Standalone exfiltration assessment. No imports, I/O or retained event state.
const PATTERNS = [
  {
    "name": "large_transfer_to_new_destination",
    "technique": "T1048",
    "relatedTechniques": [
      "T1041"
    ],
    "condition": "처음 보는 목적지로 50,000,000바이트 이상이 실제 외부 전송된 복합 신호를 찾는다. 용량이나 목적지 하나만으로 차단하지 않는다.",
    "evidence": "T1048은 기존 명령 통로와 다른 프로토콜을 통한 자료 반출을 설명한다. 새 목적지와 용량을 결합한 50MB 기준은 이 학습 정책이다.",
    "source": "https://attack.mitre.org/techniques/T1048/"
  },
  {
    "name": "repeated_large_external_transfer",
    "technique": "T1041",
    "relatedTechniques": [
      "T1048"
    ],
    "condition": "같은 목적지 또는 명령 통로로 대용량 전송이 5회 이상 반복되는 경보 요약과 전송량을 대조한다. 단일 경보의 count와 설명이 충돌하면 차단하지 않는다.",
    "evidence": "T1041은 기존 명령 통로로 데이터를 반출하는 기법이다. 반복 전송 상관 분석과 5회 기준은 학습 정책이며 기법의 고정 수치가 아니다.",
    "source": "https://attack.mitre.org/techniques/T1041/"
  },
  {
    "name": "off_hours_archive_or_repeated_transfer",
    "technique": "T1048",
    "relatedTechniques": [
      "T1041",
      "T1560"
    ],
    "condition": "검증된 경보 요약의 업무 시간 밖 신호가 압축 파일 외부 반출 또는 같은 목적지 반복 대용량 전송과 겹치는지 확인한다. 시각과 압축 파일 생성만으로 차단하지 않는다.",
    "evidence": "T1048은 다른 프로토콜로 반출하는 기법이며 T1560은 전송 전 압축을 설명한다. 압축이나 업무 시간 밖 활동 하나는 반출 성공의 증거가 아니다.",
    "source": "https://attack.mitre.org/techniques/T1048/",
    "additionalSource": "https://attack.mitre.org/techniques/T1560/"
  },
  {
    "name": "bulk_copy_or_unusual_protocol",
    "technique": "T1048",
    "relatedTechniques": [
      "T1041"
    ],
    "condition": "평소와 다른 포트/프로토콜로 다수 파일이 연속 반출되거나 짧은 시간에 전체 자료가 외부로 복사되는 신호를 용량과 함께 확인한다.",
    "evidence": "T1048은 대체 프로토콜 반출을 다루며 T1041은 기존 통로 반출을 다룬다. 포트 이상 또는 전체 복사 요약과 용량/파일 수의 조합은 학습 탐지 정책이다.",
    "source": "https://attack.mitre.org/techniques/T1048/"
  }
];

function result(confidence, pattern, detail) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: `${pattern}: ${detail}` };
}
function text(value) { return typeof value === 'string' ? value.slice(0, 4096) : ''; }
function number(value, max = 1000000000000) {
  if (typeof value !== 'number' && (typeof value !== 'string' || !/^\d{1,13}$/u.test(value))) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= 0 && n <= max ? n : null;
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
  const tags = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = prefix => tags.slice(0, 32).some(tag => typeof tag === 'string' && (tag === prefix || tag.startsWith(prefix + '.')));
  const related = tagged('T1041') || tagged('T1048');
  const level = number(rule.level, 16);
  const bytes = number(data.bytes);
  const files = number(data.files, 1000000);
  const count = number(data.count, 1000000);
  const describedCount = number(description.match(/(\d{1,7})\s*(?:번|times|transfers)/iu)?.[1], 1000000);
  const describedFiles = number(description.match(/(?:파일|자료|압축\s*파일)\s*(\d{1,7})\s*(?:건|개)/u)?.[1]
    ?? description.match(/(\d{1,7})\s*files/iu)?.[1], 1000000);
  const inconsistent = count !== null && describedCount !== null && count !== describedCount
    || files !== null && describedFiles !== null && files !== describedFiles;
  const invalidMetric = ['bytes','files','count'].some(key => data[key] !== undefined
    && number(data[key], key === 'bytes' ? 1000000000000 : 1000000) === null);
  const failed = /실패|거부|취소|전송.{0,15}(?:없|아직\s*없)|반출.{0,8}없|\bfailed\b|\bdenied\b|cancel(?:led|ed)?|no\s+(?:external\s+)?transfer|not\s+(?:sent|transferred)/iu.test(description);
  const approved = /승인된\s*(?:백업|전송|반출)|approved\s+(?:backup|transfer|export)/iu.test(description);
  const outgoing = /나갔|전송|반출|올라갔|복사|\b(?:sent|uploaded|transfer(?:red)?|copied|exfiltration)\b/iu.test(description);
  const knownDestination = /(?:처음|낯선|새로운).{0,20}(?:아닙|아님)|known\s+destination|not\s+(?:a\s+)?new\s+destination/iu.test(description);
  const newDestination = !knownDestination && /처음\s*보|처음\s*봅|처음\s*봅니다|낯선\s*(?:목적지|주소)|새(?:로운)?\s*목적지|new\s+destination|unfamiliar\s+(?:destination|address)|first[- ]seen\s+(?:destination|address)/iu.test(description);
  const offHours = /시간\s*밖|업무\s*시간\s*외|off[- ]hours|outside\s+(?:business|usual|normal)\s+hours/iu.test(description);
  const archive = /압축\s*파일|archive|compressed\s+file/iu.test(description);
  const sameDestination = /같은\s*목적지|명령\s*통로|same\s+destination|command[- ]and[- ]control|\bc2\b/iu.test(description);
  const repeated = /반복|연속|\d+\s*번|repeat|consecutive|\d+\s*(?:times|transfers)/iu.test(description);
  const attempts = count ?? describedCount ?? 0;
  const unusualProtocol = /평소에?\s*쓰지\s*않던\s*포트|낯선\s*(?:포트|프로토콜)|unusual\s+(?:port|protocol)|alternate\s+protocol/iu.test(description);
  const fullCopy = /자료실\s*전체|전체\s*자료|entire\s+(?:vault|dataset)|all\s+(?:records|data)/iu.test(description);
  const shortWindow = /짧은\s*시간|short\s+(?:time|period|window)|within\s+\d+\s*minutes/iu.test(description);
  const strong = related && level !== null && level >= 10 && validIp(data.dstip)
    && bytes !== null && bytes >= 50000000 && outgoing && !failed && !approved && !inconsistent && !invalidMetric;
  if (strong && newDestination) return result(0.96, PATTERNS[0].name, '새 목적지와 대용량 외부 전송이 겹침');
  if (strong && sameDestination && repeated && attempts >= 5) {
    return result(0.95, PATTERNS[1].name, '같은 통로로 대용량 전송 반복');
  }
  if (strong && offHours && (archive || sameDestination && attempts >= 5)) {
    return result(0.94, PATTERNS[2].name, '업무 시간 밖 압축/반복 대용량 반출');
  }
  if (strong && (unusualProtocol && repeated && files !== null && files >= 30
      || fullCopy && shortWindow && files !== null && files >= 100)) {
    return result(0.93, PATTERNS[3].name, '비정상 통로 또는 전체 자료 대량 복사');
  }
  if (related && level !== null && level >= 5) return result(0.65, 'exfiltration_review', '반출 의심 신호, 확정 차단 근거 부족');
  return result(0.1, 'no_match', '명확한 반출 근거 없음');
}

