// Standalone persistence assessment. No imports, file access, network calls or retained state.
const PATTERNS = [
  {
    "name": "suspicious_service_persistence",
    "technique": "T1543",
    "condition": "새 서비스 등록 또는 실행 파일 변경에 미서명·기준 목록 밖이라는 명확한 신호와 임시 실행 경로가 겹치거나, 미서명 등록이 같은 출발 주소에서 반복된다. 서명 확인 불가나 설명 수정만으로는 차단하지 않는다.",
    "evidence": "MITRE T1543은 부팅·반복 실행을 위해 서비스 등 시스템 프로세스를 생성하거나 변경하는 지속성을 설명한다.",
    "source": "https://attack.mitre.org/techniques/T1543/"
  },
  {
    "name": "suspicious_scheduled_task",
    "technique": "T1053",
    "condition": "낯선 예약 작업이 임시 실행 파일을 가리키거나, 시작 항목과 같은 임시 파일을 함께 사용한다. 수업 시간의 기존 작업이나 작업 이름 하나만으로 차단하지 않는다.",
    "evidence": "MITRE T1053은 예약 기능을 이용한 악성 코드의 초기·반복 실행과 원격 작업 생성을 설명한다.",
    "source": "https://attack.mitre.org/techniques/T1053/"
  },
  {
    "name": "unknown_startup_program",
    "technique": "T1547.001",
    "condition": "실제 시작 폴더에 기준 목록 밖 프로그램이 추가되는지 확인한다. 목록 읽기·변경 한 건·실행 기록 없는 경우만으로 차단하지 않는다.",
    "evidence": "시작 폴더의 로그온 자동 실행은 MITRE T1547.001에 해당한다. 과제 경보는 T1543으로 묶여 있으나 실제 기법 근거는 T1547.001이다.",
    "source": "https://attack.mitre.org/techniques/T1547/001/"
  }
];

function result(confidence, pattern, detail) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: `${pattern}: ${detail}` };
}
function text(value, limit = 4096) { return typeof value === 'string' ? value.slice(0, limit) : ''; }
function number(value) {
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
  const parts = value.split('::'); const groups = value.split(':').filter(Boolean);
  return parts.length <= 2 && (parts.length === 2 || (!value.startsWith(':') && !value.endsWith(':')))
    && groups.every(x => /^[a-f0-9]{1,4}$/iu.test(x))
    && (parts.length === 2 ? groups.length < 8 : groups.length === 8);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0, 'no_match', '경보 형식 부족');
  const rule = alert.rule && typeof alert.rule === 'object' && !Array.isArray(alert.rule) ? alert.rule : {};
  const data = alert.data && typeof alert.data === 'object' && !Array.isArray(alert.data) ? alert.data : {};
  const description = text(rule.description);
  const path = text(data.path || alert.syscheck?.path).replace(/\\/gu, '/');
  const level = number(rule.level);
  const tags = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = prefix => tags.slice(0, 32).some(tag => typeof tag === 'string' && (tag === prefix || tag.startsWith(prefix + '.')));
  const service = /서비스|\bservice\b|systemd/iu.test(description);
  const task = /예약\s*작업|scheduled\s+task|\bcron\b/iu.test(description);
  const startup = /시작\s*(?:폴더|프로그램|항목)|startup\s*(?:folder|program|entry)/iu.test(description)
    || /\/Start Menu\/Programs\/Startup\//iu.test(path);
  const noMutation = /등록(?:은|이)?\s*없|추가(?:는|가)?\s*없|변경(?:은|이)?\s*없|읽기만|read[- ]only|no\s+(?:new\s+)?(?:service|task|registration|change|addition)/iu.test(description);
  const changed = !noMutation && /새\s*서비스|new\s+service|등록|추가|바뀌|변경|생성|만들|install(?:ed|ation)?|creat(?:e|ed|ion)|register(?:ed)?|registrations?|modif(?:y|ied)|chang(?:e|ed)|added/iu.test(description);
  const unsigned = /미서명|not\s+signed|without\s+(?:a\s+)?signature|서명\s*없는|서명(?:이|은)?\s*없|\bunsigned\b|signature\s*(?:absent|invalid|missing)/iu.test(description);
  const signatureDescription = description.replace(/\bnot\s+signed\b/giu, 'unsigned');
  const signed = /서명된|서명(?:이|은)?\s*(?:유효|있)|\bsigned\s+(?:binary|service)\b|valid\s+signature/iu.test(signatureDescription);
  const unknownSignature = /서명.{0,12}(?:모릅|모름|모릅니다|모르|확인되지|아직)|signature\s*(?:unknown|unverified|not\s+verified)/iu.test(description);
  const unfamiliar = /처음\s*보|낯선|평소\s*목록에\s*없는|기준\s*목록에\s*없는|임의\s*문자열|unknown\s+(?:service|task|program)|not\s+in\s+(?:the\s+)?baseline|random\s+(?:task\s+)?name/iu.test(description);
  const usual = /평소\s*시각|그대로|실행\s*파일은\s*그대로|unchanged|approved\s+(?:service|task|change)/iu.test(description);
  const outsideHours = /시간\s*밖|outside\s+(?:usual|business|normal)\s+hours/iu.test(description);
  const startupPath = /\/Start Menu\/Programs\/Startup\//iu.test(path);
  const executable = /\.(?:exe|dll|cmd|bat|ps1|vbs|js|lnk)$/iu.test(path);
  const temporaryPath = /(?:^|\/)(?:temp|tmp)(?:\/|$)|^\/dev\/shm\//iu.test(path);
  const unsafeTarget = temporaryPath && (executable || path.startsWith('/'));
  const rawCount = number(data.count);
  const summaryCount = number(description.match(/(\d{1,7})\s*(?:건|번|times|events|registrations)/iu)?.[1]);
  const repeated = /연속|반복|repeated|consecutive/iu.test(description);
  const conflicts = rawCount !== null && summaryCount !== null && rawCount !== summaryCount;
  const attempts = rawCount ?? summaryCount ?? 0;
  const strongContext = validIp(data.srcip) && level !== null && level >= 10 && level <= 16
    && !(signed && unsigned) && !unknownSignature && !usual && !noMutation;
  const serviceEvidence = service && changed && (unsigned || unfamiliar)
    && (unsafeTarget || unsigned && repeated && attempts >= 3 && !conflicts);
  const taskEvidence = task && (unfamiliar || outsideHours || startup)
    && unsafeTarget;
  const startupEvidence = startup && startupPath && executable && unfamiliar && changed;
  if (strongContext && serviceEvidence && tagged('T1543')) return result(0.96, PATTERNS[0].name, '서비스 변경과 위험 실행 근거가 겹침');
  if (strongContext && taskEvidence && tagged('T1053')) return result(0.94, PATTERNS[1].name, '낯선 작업과 위험 실행 경로가 겹침');
  if (strongContext && startupEvidence && (tagged('T1547') || tagged('T1543'))) return result(0.93, PATTERNS[2].name, '기준 목록 밖 시작 프로그램 추가');
  const index = service ? 0 : task ? 1 : startup ? 2 : -1;
  const techniqueSignal = tagged('T1543') || tagged('T1053') || tagged('T1547');
  if (level !== null && level >= 5 && level <= 16 && (techniqueSignal || serviceEvidence || taskEvidence || startupEvidence)) {
    return result(0.65, index < 0 ? 'persistence_review' : PATTERNS[index].name, '지속성 의심 신호, 명확한 격리 근거 부족');
  }
  return result(0.1, 'no_match', '지속성 악용을 확정할 근거 없음');
}
