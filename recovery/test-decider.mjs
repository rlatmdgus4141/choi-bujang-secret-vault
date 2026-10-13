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

// Route authorization only. The contract has no owner or instructor role.
// Individual ownership and current instructor authority are rechecked by the final API.
function resourceRouteAllowed(request) {
  if (!['notes', 'notices'].includes(request.service) || typeof request.path !== 'string'
      || typeof request.route !== 'string' || request.queryLength !== 0) return false;
  return [`/${request.service}`, `/api/${request.service}`].some(base => {
    if (request.path === base && request.route === `${request.method} ${base}`) {
      // No unscoped personal-note listing. Notice reads are shared; no notice writes are authorized here.
      return request.service === 'notes' ? request.method === 'POST' : request.method === 'GET';
    }
    if (!request.path.startsWith(`${base}/`) || request.route !== `${request.method} ${base}/:id`) return false;
    const id = request.path.slice(base.length + 1);
    // Safe opaque resource IDs include the documented practice ID; functional endpoints are never IDs.
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(id)
        || /^(?:export|list|all|search|bulk|download|admin|notices|announcements|instructor)$/iu.test(id)) return false;
    return (request.service === 'notes' ? ['GET', 'PUT', 'DELETE'] : ['GET']).includes(request.method);
  });
}

export async function decide(request) {
  const reply = (decision, reasonCode, ruleId) => ({
    schema: 'aleph.decision.v1', requestId: request?.requestId,
    decision, reasonCode, ruleIds: [ruleId],
  });
  if (request?.deviceRegistered !== true) {
    return reply('deny', 'device_not_registered', 'device_registered');
  }
  if (request.schema !== 'aleph.decision.v1'
      || !['classId', 'projectId', 'subjectId'].every(key => typeof request[key] === 'string'
        && request[key].length > 0 && request[key].length <= 256 && !/[\s*]/u.test(request[key]))
      || typeof request.deviceId !== 'string' || !/^[a-f0-9]{16}$/u.test(request.deviceId)) {
    return reply('deny', 'starter_not_ready', 'starter.deny');
  }
  const context = connectionContext(request);
  if (!context) return reply('deny', 'starter_not_ready', 'starter.deny');
  if (!resourceRouteAllowed(request)) return reply('deny', 'starter_not_ready', 'resource_zones');
  if (context.source === 'judge_fixture' && context.riskCount >= 2 && !recentlyVerified(request.stepUp)) {
    return reply('step_up', 'step_up_required', 'step_up_required');
  }
  return reply('allow', 'approved', 'resource_zones');
}
