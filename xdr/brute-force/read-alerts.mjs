import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const DEFAULT_FIXTURE = new URL('../fixtures/brute-force.json', import.meta.url);

function safeText(value, limit = 1024) {
  if (typeof value !== 'string') return '';
  return value.slice(0, limit)
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/gu, '[redacted]')
    .replace(/\b(?:sb_secret_|sb_publishable_|sk-)[A-Za-z0-9_-]+/gu, '[redacted]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gu, '[redacted]')
    .replace(/\bBearer\s+[^\s,;]+/giu, 'Bearer [redacted]')
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호|비밀값)\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s,;]+)/giu, '$1[redacted]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, '[redacted]')
    .replace(/[\r\n\u0000-\u001f\u007f]+/gu, ' ');
}

export function projectAlerts(alerts) {
  if (!Array.isArray(alerts)) throw new TypeError('invalid_alert_list');
  return alerts.map(alert => {
    const ip = typeof alert?.data?.srcip === 'string' ? alert.data.srcip : '';
    const level = Number(alert?.rule?.level);
    const timestamp = typeof alert?.timestamp === 'string' ? alert.timestamp : '';
    return {
      timestamp: timestamp && Number.isFinite(Date.parse(timestamp)) ? new Date(timestamp).toISOString() : null,
      sourceIp: isIP(ip) ? ip : null,
      account: safeText(alert?.data?.srcuser, 160),
      level: Number.isInteger(level) && level >= 0 && level <= 16 ? level : null,
      description: safeText(alert?.rule?.description),
    };
  });
}

export async function readAlerts(path = DEFAULT_FIXTURE) {
  let fixture;
  try { fixture = JSON.parse(await readFile(path, 'utf8')); }
  catch { throw new Error('invalid_brute_force_fixture'); }
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force') {
    throw new Error('invalid_brute_force_fixture');
  }
  return projectAlerts(fixture.alerts);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const rows = await readAlerts();
    for (const row of rows) console.log(JSON.stringify(row));
    console.log(`경보 ${rows.length}건 · 뽑은 줄 ${rows.length}개`);
  } catch { console.error('경보 읽기에 실패했습니다. 공식 경보 파일 형식을 확인하세요.'); process.exitCode = 1; }
}
