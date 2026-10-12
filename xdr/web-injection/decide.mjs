// Standalone and deterministic. Thresholds are local training policy, not MITRE constants.
const PATTERNS = [
  {
    "name": "sql_injection",
    "technique": "T1190",
    "condition": "요청 인자의 UNION SELECT·조건식·SQL 문장 연결 또는 상관 경보의 SQL 주입 요약을 확인한다. 단순 SQL/select 단어는 차단하지 않는다.",
    "thresholds": {
      "blockCount": 5,
      "minRuleLevel": 10,
      "maxWindowSeconds": 300
    },
    "evidence": "MITRE T1190은 공개 앱을 통한 SQL 주입 악용 사례를 포함한다.",
    "source": "https://attack.mitre.org/techniques/T1190/"
  },
  {
    "name": "script_injection",
    "technique": "T1190",
    "condition": "script 태그·이벤트 처리 속성·스크립트 삽입 경보를 찾는다. 수업명 script나 부정된 삽입 설명만으로 차단하지 않는다.",
    "thresholds": {
      "blockCount": 5,
      "minRuleLevel": 10,
      "maxWindowSeconds": 300
    },
    "evidence": "공개 웹 앱 악용이라는 T1190 과제 범주에서, OWASP가 설명하는 사용자 입력의 스크립트 주입 형태를 관찰한다. 모든 XSS를 T1190 초기 접근으로 단정하지 않는다.",
    "source": "https://owasp.org/www-community/attacks/xss/"
  },
  {
    "name": "path_traversal",
    "technique": "T1190",
    "condition": "두 단계 이상의 ../ 또는 ..\\ 시퀀스와 경로 이탈 상관 경보를 찾는다. up 같은 일반 단어는 차단하지 않는다.",
    "thresholds": {
      "blockCount": 5,
      "minRuleLevel": 10,
      "maxWindowSeconds": 300
    },
    "evidence": "MITRE T1190 악용 사례에는 디렉터리 순회가 있으며 OWASP는 상위 경로 시퀀스로 허용 경로 밖 파일에 접근하는 형태를 설명한다.",
    "source": "https://owasp.org/www-community/attacks/Path_Traversal"
  },
  {
    "name": "command_injection",
    "technique": "T1190",
    "condition": "명령 구분자와 명령 구문의 조합 또는 명령 구분자 주입 상관 경보를 찾는다. 구분자 한 글자만으로 차단하지 않는다.",
    "thresholds": {
      "blockCount": 5,
      "minRuleLevel": 10,
      "maxWindowSeconds": 300
    },
    "evidence": "MITRE T1190에는 명령 주입 취약점 악용 사례가 있으며 OWASP는 외부 입력이 운영체제 명령에 전달되는 주입을 설명한다.",
    "source": "https://owasp.org/www-community/attacks/Command_Injection"
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


// Input strings are inspected as data only. No eval, retained event state or external calls.
function text(value, limit) { return typeof value === 'string' ? value.slice(0, limit) : ''; }
function decode(value) {
  let out = value.replace(/\+/gu, ' ');
  for (let i = 0; i < 2; i++) {
    try { const next = decodeURIComponent(out); if (next === out) break; out = next; }
    catch { break; }
  }
  return out;
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0, 'no_match: 경보 형식 부족');
  const rule = alert.rule && typeof alert.rule === 'object' ? alert.rule : {};
  const data = alert.data && typeof alert.data === 'object' ? alert.data : {};
  const description = text(rule.description, 2048);
  const rawUrl = text(data.url, 8192);
  const level = count(rule.level);
  const mitre = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = mitre.slice(0, 32).includes('T1190');
  // Do not inspect credential fields or use fixture IDs / placeholder names as attack evidence.
  const url = decode(rawUrl);
  const query = url.includes('?') ? url.slice(url.indexOf('?') + 1) : '';
  const sqlQuery = query.replace(/\/\*[\s\S]*?\*\//gu, ' ');
  const rawSql = /\bunion\s+(?:all\s+)?select\b|\b(?:or|and)\s+['"]?(\d{1,12})['"]?\s*=\s*['"]?\1(?:['"\s;&-]|$)|;\s*(?:select|drop|delete|insert|update)\b/iu.test(sqlQuery);
  const rawScript = /<\s*script(?:\s|>|\/)|<[^>\r\n]{0,256}\s+on[a-z]+\s*=|\bjavascript\s*:/iu.test(query);
  const rawTraversal = /(?:\.\.[/\\]){2,}/u.test(url);
  const rawCommand = /(?:;|\|\||&&|\|)\s*(?:id|whoami|cat|curl|wget|sh|bash|powershell|cmd)(?:\s|$|[;&|])|\$\(\s*(?:id|whoami|cat|curl|wget)\b/iu.test(query);
  const negated = /(?:표기|표식|공격|삽입|주입).{0,24}(?:없|아닙|아니|아님)|no\s+(?:injection|attack)|not\s+(?:an?\s+)?(?:injection|attack)/iu.test(description);
  const described = !negated;
  const matches = [
    rawSql || (described && /SQL\s*(?:구문|표식|주입)|데이터베이스\s*조회를\s*이어|sql\s+injection/iu.test(description)),
    rawScript || (described && /스크립트\s*(?:삽입|표식|주입)|script\s+injection|cross[- ]site\s+scripting/iu.test(description)),
    rawTraversal || (described && /경로.{0,20}(?:거슬러|이탈)|path\s+traversal|directory\s+traversal/iu.test(description)),
    rawCommand || (described && /명령\s*(?:구분자|주입)|command\s+injection/iu.test(description)),
  ];
  const index = matches.findIndex(Boolean);
  const numericCount = count(data.count);
  const describedCount = count(description.match(/(\d{1,7})\s*(?:번|건|times|requests|attempts)/iu)?.[1]);
  const attempts = numericCount ?? describedCount ?? 0;
  const conflicting = numericCount !== null && describedCount !== null && numericCount !== describedCount;
  const noRepeat = /반복(?:은|이)?\s*없|반복되지\s*않|단발|한\s*번|single\s+(?:request|attempt)|no\s+repeat/iu.test(description);
  const timeMatch = description.match(/(\d+)\s*(초|분|시간|일|seconds?|minutes?|hours?|days?)/iu);
  const duration = timeMatch ? Number(timeMatch[1]) * (/^(초|seconds?)$/iu.test(timeMatch[2]) ? 1
    : /^(분|minutes?)$/iu.test(timeMatch[2]) ? 60 : /^(시간|hours?)$/iu.test(timeMatch[2]) ? 3600 : 86400) : null;
  const windowValue = data.window_seconds;
  const explicitWindow = windowValue === undefined ? null : count(windowValue);
  const policy = PATTERNS[index < 0 ? 0 : index];
  const windowOk = (duration === null || duration > 0 && duration <= policy.thresholds.maxWindowSeconds)
    && (windowValue === undefined || explicitWindow !== null && explicitWindow > 0 && explicitWindow <= policy.thresholds.maxWindowSeconds);
  const summaryRepeated = /반복|연속|이어|번갈아|같은\s*주소|한\s*주소|same\s+(?:ip|source)|repeat|consecutive/iu.test(description);
  const rawEvidence = rawSql || rawScript || rawTraversal || rawCommand;
  // data.count is a trusted per-source Wazuh correlation summary, not a counter accumulated by this module.
  const correlated = index >= 0 && validIp(data.srcip) && rawUrl.length > 0 && tagged
    && level !== null && level >= policy.thresholds.minRuleLevel && level <= 16
    && attempts >= policy.thresholds.blockCount && !conflicting && !noRepeat && windowOk
    && (summaryRepeated || rawEvidence);
  if (correlated) return result(duration === null && explicitWindow === null ? 0.9 : 0.96,
    `${policy.name}: 동일 출발 주소의 반복 주입 근거 확인`);
  if (index >= 0) return result(0.7, `${policy.name}: 의심 신호, 반복·상관 근거 부족`);
  if (tagged && level !== null && level >= 5 && level <= 16) {
    return result(0.55, 'web_injection_review: T1190 의심 경보, 명확한 주입 패턴 미확인');
  }
  return result(0.1, 'no_match: 웹 주입 패턴 근거 없음');
}
