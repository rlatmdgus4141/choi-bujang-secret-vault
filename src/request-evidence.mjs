import { randomUUID } from 'node:crypto';
export function routeLabel(url = '') {
  const path = url.split('?')[0];
  if (/^\/api\/(notes|notices)\/[^/]+$/.test(path)) return path.replace(/[^/]+$/, ':id');
  return ['/api/auth','/api/device','/api/notes','/api/notices','/api/restore','/api/operations'].includes(path) ? path : '/api/other';
}
// A fixed projection: never serialize a request, body, token, owner, URL query or note ID.
export function attachEvidence(req, res, env = process.env, log = console.info) {
  if (res.vaultEvidence) return;
  res.vaultEvidence = true;
  const requestId = randomUUID(), original = res.json;
  res.json = function(body) {
    const checkedAt = new Date().toISOString();
    const record = {schema:'aleph.api.observation.v1', requestId, checkedAt,
      method:['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'].includes(req.method) ? req.method : 'OTHER',
      route:routeLabel(req.url), status:this.statusCode};
    this.setHeader('X-Vault-Request-Id',requestId);
    this.setHeader('X-Vault-Checked-At',checkedAt);
    if (env.VERCEL === '1') log(JSON.stringify(record));
    return original.call(this,body);
  };
}
