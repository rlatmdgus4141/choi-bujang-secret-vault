// Public wire format only. No credential, token or private key is stored here.
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const requestMessage = (owner, id, method, path, hash, at, nonce) =>
  JSON.stringify(['aleph.app.request.v1', owner, id, method, path, hash, at, nonce]);
export const approvalMessage = (owner,id,challenge) => JSON.stringify(['aleph.app.approval.v1',owner,id,challenge]);
