// Standalone, deterministic detection only. No imports, storage, network or payload execution.
const PATTERNS = [
  {
    "name": "log4shell_remote_lookup",
    "technique": "T1190",
    "cve": "CVE-2021-44228",
    "condition": "요청 주소·인자·머리글 안의 완전한 JNDI LDAP/LDAPS/RMI 원격 조회 구문을 찾는다. 한 건이라도 구문과 출발 주소가 명확할 때만 차단 후보로 삼는다.",
    "evidence": "Apache의 CVE-2021-44228 설명은 공격자가 통제한 로그·인자의 JNDI LDAP 등 원격 엔드포인트로 임의 코드 실행이 가능함을 명시한다.",
    "source": "https://logging.apache.org/security.html#cve-2021-44228"
  },
  {
    "name": "log4shell_partial_or_probe",
    "technique": "T1190",
    "cve": "CVE-2021-44228",
    "condition": "불완전한 JNDI 구문·DNS 조회형 점검 또는 T1190 상관 경보를 검토한다. 취약점 이름과 jndi 단어만으로 차단하지 않는다.",
    "evidence": "MITRE T1190은 인터넷 공개 앱의 취약점 악용을 다룬다. 이름이나 불완전한 흔적은 성공한 악용의 증거가 아니므로 알림에만 사용한다.",
    "source": "https://attack.mitre.org/techniques/T1190/"
  },
  {
    "name": "known_cve_scanner_review",
    "technique": "T1190",
    "cve": "CVE-2021-44228",
    "condition": "log4j-scan 등 취약점 전용 점검 도구 흔적을 확인한다. 점검 도구 이름만 있는 요청은 알림으로 남기며 일반 curl·브라우저 이름은 근거로 삼지 않는다.",
    "evidence": "log4j-scan 공식 저장소는 HTTP 머리글과 GET/POST 인자 등을 검사하는 CVE-2021-44228 점검 도구임을 설명한다. 도구 흔적은 검토 근거이며 악용 확정 근거는 아니다.",
    "source": "https://github.com/fullhunt/log4j-scan"
  }
];

function result(confidence, pattern, detail) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason: `${pattern}: ${detail}` };
}

function text(value, limit = 8192) { return typeof value === 'string' ? value.slice(0, limit) : ''; }
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

// Decode text without evaluating lookups, reading environment variables or opening destinations.
function normalize(value) {
  let out = text(value);
  for (let i = 0; i < 2; i++) {
    out = out.replace(/(?:%[0-9a-f]{2})+/giu, part => {
      try { return decodeURIComponent(part); } catch { return part; }
    });
  }
  out = out.replace(/\\u([0-9a-f]{4})/giu, (_, code) => String.fromCharCode(parseInt(code, 16)))
    .replace(/&#(?:x([0-9a-f]{1,4})|(\d{1,5}));/giu,
      (_, hex, decimal) => String.fromCharCode(parseInt(hex || decimal, hex ? 16 : 10)));
  for (let i = 0; i < 6; i++) {
    const next = out.replace(/\$\{(lower|upper):([^{}]{1,64})\}/giu,
      (_, operation, literal) => operation.toLowerCase() === 'lower' ? literal.toLowerCase() : literal.toUpperCase())
      .replace(/\$\{::?-([^{}]{1,64})\}/gu, '$1');
    if (next === out) break;
    out = next;
  }
  return out;
}

function requestFields(data) {
  const fields = ['url', 'uri', 'request_uri', 'useragent', 'user_agent', 'query_string', 'args', 'body', 'request_body'];
  const values = fields.map(name => text(data[name])).filter(Boolean);
  const headers = data.headers;
  if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
    for (const [name, value] of Object.entries(headers).slice(0, 24)) {
      // Credentials are never used as a detection signal or copied into the result.
      if (!/^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)$/iu.test(name)) {
        if (Array.isArray(value)) values.push(...value.slice(0, 4).map(x => text(x)).filter(Boolean));
        else if (typeof value === 'string') values.push(text(value));
      }
    }
  }
  return values.slice(0, 40).map(normalize);
}

export function decide(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return result(0, 'no_match', '경보 형식 부족');
  const data = alert.data && typeof alert.data === 'object' && !Array.isArray(alert.data) ? alert.data : {};
  const rule = alert.rule && typeof alert.rule === 'object' && !Array.isArray(alert.rule) ? alert.rule : {};
  const values = requestFields(data);
  const complete = values.some(value => /\$\{\s*jndi\s*:\s*(?:ldaps?|rmi)\s*:\/\/(?:\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*)(?::\d{1,5})?(?:\/[^{}\s]*)?\s*\}/iu.test(value));
  const partial = values.some(value => /\$\{\s*jndi\s*:/iu.test(value));
  const scanner = values.some(value => /\blog4j[-_]?scan(?:ner)?\b|\blog4shell[-_]?scan(?:ner)?\b|\bCVE-2021-44228[-_](?:scan|check|probe)\b/iu.test(value));
  const ids = Array.isArray(rule.mitre) ? rule.mitre : Array.isArray(rule.mitre?.id) ? rule.mitre.id : [];
  const tagged = ids.slice(0, 32).includes('T1190');
  const numeric = typeof rule.level === 'number' ? rule.level
    : typeof rule.level === 'string' && /^\d{1,2}$/u.test(rule.level) ? Number(rule.level) : null;
  const level = Number.isInteger(numeric) && numeric >= 0 && numeric <= 16 ? numeric : null;
  if (complete) {
    return validIp(data.srcip) ? result(tagged && level >= 10 ? 0.97 : 0.9, PATTERNS[0].name, '요청에 완전한 원격 조회 구문')
      : result(0.75, PATTERNS[0].name, '원격 조회 구문 확인, 출발 주소 검토 필요');
  }
  if (partial) return result(0.75, PATTERNS[1].name, '불완전한 조회 또는 원격 점검 구문');
  if (scanner) return result(0.65, PATTERNS[2].name, '전용 점검 도구 흔적, 악용 구문 미확인');
  if (tagged && level !== null && level >= 5) return result(0.55, PATTERNS[1].name, '상관 경보 검토, 악용 구문 미확인');
  return result(0.1, 'no_match', '알려진 악용 형태의 근거 없음');
}
