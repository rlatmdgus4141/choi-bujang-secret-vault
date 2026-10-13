// Only the class engine may call this policy after authenticating identity, device and route.
// Do not expose this as an API accepting browser-supplied deviceRegistered or subjectId.
export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered']);

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
  if (request.schema === 'aleph.decision.v1' && identityPresent && devicePresent
      && request.service === 'notes' && request.method === 'GET' && readRoute) {
    return reply('allow', 'approved', 'device_registered');
  }
  // Preserve the starter's default denial outside the single implemented read rule.
  return reply('deny', 'starter_not_ready', 'starter.deny');
}
