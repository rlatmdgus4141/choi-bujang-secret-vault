// Only the class engine may call this policy after authenticating identity, device and route.
// Do not expose this as an API accepting browser-supplied deviceRegistered or subjectId.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'step_up_required', 'resource_zones']);

// Explicit access grant for the documented synthetic resource in scripts/fixture-7.mjs.
// These public practice identifiers are NOT real users or inferred production ownership.
// No grant is learned from incoming requests; changing any scope component must deny demo access.
const PRACTICE_READ_GRANT = Object.freeze({
  classId: 'class_fixture', projectId: 'project_fixture', subjectId: 'learner_fixture',
  deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes', method: 'GET',
  path: '/notes/demo', route: 'GET /notes/:id',
});


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

const GRANT_FIELDS = Object.freeze([
  'classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route',
]);

// Syntax only. Passing this function is never an authorization decision.
function knownResourceRoute(grant) {
  if (!['notes', 'notices'].includes(grant.service)) return false;
  return [`/${grant.service}`, `/api/${grant.service}`].some(base => {
    if (grant.path === base && grant.route === `${grant.method} ${base}`) {
      return ['GET', 'POST'].includes(grant.method);
    }
    if (!grant.path.startsWith(`${base}/`) || grant.route !== `${grant.method} ${base}/:id`) return false;
    const id = grant.path.slice(base.length + 1);
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(id);
    if (!uuid) return grant.path === '/notes/demo' && grant.service === 'notes' && grant.method === 'GET';
    return (grant.service === 'notes' ? ['GET', 'PUT', 'DELETE'] : ['GET', 'PUT']).includes(grant.method);
  });
}

// Server initialization only. This factory is not an HTTP API and never reads grants from requests.
// Enrollment must provide engine pseudonyms; raw Supabase UUIDs are not inferred to be subjectIds.
export function createDecider({ grants = [] } = {}) {
  if (!Array.isArray(grants)) throw new TypeError('Invalid resource policy');
  const policy = Object.freeze(grants.map(grant => {
    if (!grant || typeof grant !== 'object' || Array.isArray(grant)
        || Object.keys(grant).length !== GRANT_FIELDS.length
        || !GRANT_FIELDS.every(key => Object.hasOwn(grant, key))
        || !GRANT_FIELDS.every(key => typeof grant[key] === 'string' && grant[key].length > 0
          && grant[key].length <= 256 && !/[\s*]/u.test(key === 'route'
            ? grant[key].replace(/^[A-Z]+ /u, '') : grant[key]))
        || !/^[a-f0-9]{16}$/u.test(grant.deviceId) || !knownResourceRoute(grant)) {
      throw new TypeError('Invalid resource grant');
    }
    return Object.freeze(Object.fromEntries(GRANT_FIELDS.map(key => [key, grant[key]])));
  }));
  return async function decide(request) {
    const reply = (decision, reasonCode, ruleId) => ({
      schema: 'aleph.decision.v1', requestId: request?.requestId,
      decision, reasonCode, ruleIds: [ruleId],
    });
    if (request?.deviceRegistered !== true) {
      return reply('deny', 'device_not_registered', 'device_registered');
    }
    if (request.schema !== 'aleph.decision.v1') {
      return reply('deny', 'starter_not_ready', 'starter.deny');
    }
    const context = connectionContext(request);
    if (!context) return reply('deny', 'starter_not_ready', 'starter.deny');
    const granted = request.queryLength === 0 && policy.some(grant =>
      GRANT_FIELDS.every(key => request[key] === grant[key]));
    // Exact permission is required even for a syntactically valid UUID, a list, or a fresh login.
    if (!granted || request.path === '/notes/demo' && context.source !== 'judge_fixture') {
      return reply('deny', 'starter_not_ready', 'resource_zones');
    }
    if (context.source === 'judge_fixture' && context.riskCount >= 2 && !recentlyVerified(request.stepUp)) {
      return reply('step_up', 'step_up_required', 'step_up_required');
    }
    return reply('allow', 'approved', 'resource_zones');
  };
}

// Only the documented synthetic resource is enrolled in the distributed exercise policy.
// Unenrolled live resources fail closed. The existing browser API keeps its DB owner checks.
const defaultDecider = createDecider({ grants: [PRACTICE_READ_GRANT] });
export async function decide(request) {
  return defaultDecider(request);
}
