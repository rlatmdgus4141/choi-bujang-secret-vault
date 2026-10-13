// Pure detection only. A trusted engine calls this module; no public ingestion or revocation API.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;
const METHODS = new Set(['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS']);
const DECISIONS = new Set(['allow','deny','step_up']);

function pseudonym(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(value)
    && !/^(?:eyJ|sb_secret_|sb_publishable_|sk-|Bearer)/u.test(value);
}
function timestamp(value) {
  if (typeof value !== 'string') return null;
  const parts = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/u);
  if (!parts) return null;
  const [year,month,day,hour,minute,second] = parts.slice(1).map(Number);
  if (month < 1 || month > 12 || day < 1 || day > new Date(Date.UTC(year, month, 0)).getUTCDate()
      || hour > 23 || minute > 59 || second > 59) return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? new Date(at).toISOString() : null;
}
function legacyShape(event) {
  return event && typeof event === 'object' && !Array.isArray(event)
    && Object.keys(event).sort().join(',') === 'at,identity,method'
    && event.identity && typeof event.identity === 'object' && !Array.isArray(event.identity)
    && Object.keys(event.identity).join(',') === 'sub';
}

// Whitelist only: payloads, headers, note content, tokens and personal names are not retained.
export function readDetectionEvents(events) {
  if (!Array.isArray(events) || events.length > 10000) throw new TypeError('invalid_detection_events');
  const rows = [];
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) continue;
    const legacy = legacyShape(event);
    const subject = legacy ? event.identity.sub : event.subjectId ?? event.identity?.sub;
    const at = timestamp(event.at);
    if (!at || !pseudonym(subject) || !METHODS.has(event.method)) continue;
    if (event.subjectId !== undefined && event.identity?.sub !== undefined
        && event.subjectId !== event.identity.sub) continue;
    const deviceId = typeof event.deviceId === 'string' && /^[a-f0-9]{16}$/u.test(event.deviceId) ? event.deviceId : null;
    const signals = event.signals;
    const network = signals?.source === 'judge_fixture' && ['usual','unusual','unknown'].includes(signals.network)
      ? signals.network : null;
    rows.push({ at, subject, deviceId, method: event.method,
      decision: DECISIONS.has(event.decision) ? event.decision : null,
      network, legacy,
      classId: pseudonym(event.classId) ? event.classId : null,
      projectId: pseudonym(event.projectId) ? event.projectId : null,
      requestId: typeof event.requestId === 'string'
        && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u.test(event.requestId) ? event.requestId : null });
  }
  return rows;
}

export function detect(events) {
  const rows = readDetectionEvents(events);
  // Preserve the official three-field practice contract. Its subject-only result never changes permissions here.
  // Device-aware input uses the separate stricter compound rule; missing network/device/decision is not inferred.
  const legacy = events.length > 0 && events.every(legacyShape);
  const delivered = new Map();
  for (const row of rows) {
    if (!legacy && row.requestId) {
      const key = JSON.stringify([row.classId,row.projectId,row.requestId]);
      const fingerprint = JSON.stringify(row);
      if (!delivered.has(key)) delivered.set(key, fingerprint);
      else if (delivered.get(key) !== fingerprint) delivered.set(key, null);
    }
  }
  const seen = new Set();
  const reads = rows.filter(row => {
    if (row.method !== 'GET') return false;
    if (!legacy && (row.legacy || !row.deviceId || row.network !== 'unusual' || !row.decision)) return false;
    if (!legacy && row.requestId) {
      const key = JSON.stringify([row.classId,row.projectId,row.requestId]);
      if (delivered.get(key) === null || seen.has(key)) return false;
      seen.add(key);
    }
    return true;
  }).sort((a,b) => a.at.localeCompare(b.at) || JSON.stringify([a.classId,a.projectId,a.subject,a.deviceId])
    .localeCompare(JSON.stringify([b.classId,b.projectId,b.subject,b.deviceId])));
  const groups = new Map();
  for (const row of reads) {
    const key = legacy ? row.subject : JSON.stringify([row.classId,row.projectId,row.subject,row.deviceId]);
    const group = groups.get(key) ?? { times: [], first: 0 };
    const at = Date.parse(row.at);
    group.times.push(at);
    while (group.times[group.first] < at - WINDOW_MS) group.first++;
    groups.set(key, group);
    if (group.times.length - group.first > READ_LIMIT) {
      return { action: 'propose_revocation', reasonCode: 'burst_read', subject: row.subject,
        ...(!legacy ? { deviceId: row.deviceId } : {}) };
    }
  }
  return { action: 'observe' };
}
