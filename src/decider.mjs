// Only the class engine may call this policy after authenticating identity, device and route.
// Do not expose this as an API accepting browser-supplied deviceRegistered or subjectId.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required', 'resource_zones']);

// Only engine-delivered fields are inspected. Missing values stay missing; headers are never read.
function connectionContext(request) {
  const signals = request.signals;
  const events = request.recentEvents;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)
      || !Array.isArray(events) || events.length > 12
      || !events.every(event => event && typeof event.kind === 'string'
        && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0
        && Number.isSafeInteger(event.count) && event.count >= 0)) return null;
  if (signals.source === 'none') {
    // The live engine supplies no location/network evidence. Do not turn it into a local/usual value.
    if (signals.region !== 'unknown' || signals.network !== 'unknown'
        || !(signals.hour === null || Number.isInteger(signals.hour) && signals.hour >= 0 && signals.hour <= 23)) return null;
    return { source: 'none', riskCount: 0 };
  }
  if (signals.source !== 'judge_fixture'
      || !['local', 'foreign', 'unknown'].includes(signals.region)
      || !['usual', 'unusual', 'unknown'].includes(signals.network)
      || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) return null;
  const recentCount = events.filter(event => event.kind === 'risk_signal' && event.ageSeconds <= 300)
    .reduce((sum, event) => Math.min(1000000, sum + event.count), 0);
  const riskCount = Number(signals.region === 'foreign')
    + Number(signals.hour < 6) + Number(signals.network === 'unusual') + Number(recentCount >= 10);
  return { source: 'judge_fixture', riskCount };
}

function recentlyVerified(stepUp) {
  return stepUp && typeof stepUp === 'object' && !Array.isArray(stepUp)
    && stepUp.verified === true && Number.isFinite(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= 900;
}

export async function decide(request) {
  const reply = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1', requestId: request?.requestId,
    decision, reasonCode, ruleIds: [ruleId],
  });
  if (request?.deviceRegistered !== true) {
    return reply('deny', 'device_not_registered', 'device_registered');
  }
  const identityPresent = typeof request.subjectId === 'string' && request.subjectId.trim().length > 0;
  const devicePresent = typeof request.deviceId === 'string' && /^[a-f0-9]{16}$/u.test(request.deviceId);
  // Route is an engine-confirmed method/template pair, never a prefix or browser selector.
  // Live resources use the same UUID format as the final API. Arbitrary slugs are not resource IDs.
  // Keep the starter's documented read-only /notes/demo practice resource; it is not a live UUID.
  const zoneRoute = ['notes', 'notices'].some(resource => {
    if (request.service !== resource) return false;
    return [`/${resource}`, `/api/${resource}`].some(base => {
      const list = request.path === base && request.route === `${request.method} ${base}`;
      const id = typeof request.path === 'string' && request.path.startsWith(`${base}/`)
        ? request.path.slice(base.length + 1) : '';
      const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(id);
      const practiceRead = resource === 'notes' && base === '/notes'
        && id === 'demo' && request.method === 'GET';
      const item = (uuid || practiceRead) && request.route === `${request.method} ${base}/:id`;
      // No teacher/ownership assertion exists in this contract. Notices mutations fail closed here.
      // A notes allow is only the route gate: the final API must atomically constrain owner_id.
      return resource === 'notes'
        ? list && ['GET', 'POST'].includes(request.method) || item && ['GET', 'PUT', 'DELETE'].includes(request.method)
        : request.method === 'GET' && (list || item);
    });
  });
  const context = connectionContext(request);
  if (!context) return reply('deny', 'starter_not_ready', 'starter.deny');
  if (!zoneRoute || request.queryLength !== 0) return reply('deny', 'starter_not_ready', 'resource_zones');
  // Registration always wins over step-up. Only the trusted engine can attest a fresh same-identity login.
  // A fixture simulates that attestation; this module never creates it from a token or client header.
  if (request.schema === 'aleph.decision.v1' && identityPresent && devicePresent
      && ['notes', 'notices'].includes(request.service) && context.source === 'judge_fixture' && context.riskCount >= 2
      && !recentlyVerified(request.stepUp)) {
    return reply('step_up', 'step_up_required', 'step_up_required');
  }
  if (request.schema === 'aleph.decision.v1' && identityPresent && devicePresent
      && zoneRoute && request.queryLength === 0) {
    return reply('allow', 'approved', 'resource_zones');
  }
  // Unknown resource, method, path, query or absent authority stays denied.
  return reply('deny', 'starter_not_ready', 'starter.deny');
}
