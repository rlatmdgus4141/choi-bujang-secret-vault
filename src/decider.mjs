// Only the class engine may call this policy after authenticating identity, device and route.
// Do not expose this as an API accepting browser-supplied deviceRegistered or subjectId.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required']);

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
  const readRoute = ['/notes', '/api/notes'].some(base =>
    (request.route === `GET ${base}` && request.path === base)
    || (request.route === `GET ${base}/:id` && typeof request.path === 'string'
      && request.path.startsWith(`${base}/`)
      && /^[A-Za-z0-9_-]+$/u.test(request.path.slice(base.length + 1))));
  const context = connectionContext(request);
  if (!context) return reply('deny', 'starter_not_ready', 'starter.deny');
  // Registration always wins over step-up. Only the trusted engine can attest a fresh same-identity login.
  // A fixture simulates that attestation; this module never creates it from a token or client header.
  if (request.schema === 'aleph.decision.v1' && identityPresent && devicePresent
      && request.service === 'notes' && context.source === 'judge_fixture' && context.riskCount >= 2
      && !recentlyVerified(request.stepUp)) {
    return reply('step_up', 'step_up_required', 'step_up_required');
  }
  if (request.schema === 'aleph.decision.v1' && identityPresent && devicePresent
      && request.service === 'notes' && request.method === 'GET' && readRoute) {
    return reply('allow', 'approved', 'device_registered');
  }
  // Preserve the starter's default denial outside the single implemented read rule.
  return reply('deny', 'starter_not_ready', 'starter.deny');
}
