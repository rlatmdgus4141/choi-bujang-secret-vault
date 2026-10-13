import { createHash, createHmac, createPublicKey, timingSafeEqual, verify, randomUUID } from 'node:crypto';
import { canonical, requestMessage, approvalMessage } from '../public/device-protocol.js';
import { UUID } from './resources.mjs';
import config from '../aleph.config.json' with { type: 'json' };
export const digest = value => createHash('sha256').update(value).digest('hex');
export function publicDeviceKey(value) {
  if (!value || value.d || value.kty !== 'EC' || value.crv !== 'P-256'
      || ![value.x,value.y].every(s => typeof s === 'string' && /^[A-Za-z0-9_-]{43}$/u.test(s))) throw new Error('invalid_public_key');
  const key={kty:'EC',crv:'P-256',x:value.x,y:value.y};
  createPublicKey({key,format:'jwk'});
  return key;
}
const grantMac = (secret,payload) => createHmac('sha256',secret).update(`aleph.device.enrollment.v1:${config.publicAppUrl}:${payload}`).digest();
export function issueEnrollmentGrant(secret,owner,keyHash,now=Date.now()) {
  if (!secret?.startsWith('sb_secret_') || !UUID.test(owner??'') || !/^[a-f0-9]{64}$/u.test(keyHash??'')) throw new Error('invalid_enrollment');
  const payload=Buffer.from(JSON.stringify({v:1,sub:owner,kh:keyHash,n:randomUUID(),exp:now+180000})).toString('base64url');
  return `${payload}.${grantMac(secret,payload).toString('base64url')}`;
}
export function verifyEnrollmentGrant(secret,grant,owner,keyHash,now=Date.now()) {
  try {
    if (!secret?.startsWith('sb_secret_') || typeof grant!=='string' || grant.length>1500) return null;
    const parts=grant.split('.'); if(parts.length!==2) return null;
    const mac=Buffer.from(parts[1],'base64url'),expected=grantMac(secret,parts[0]);
    if(mac.length!==expected.length||!timingSafeEqual(mac,expected))return null;
    const data=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));
    return data.v===1&&data.sub===owner&&data.kh===keyHash&&UUID.test(data.n??'')
      &&Number.isSafeInteger(data.exp)&&data.exp>now&&data.exp<=now+180000 ? data : null;
  } catch {return null;}
}
function validSignature(key,message,signature) {
  try {
    if(typeof signature!=='string'||!/^[A-Za-z0-9_-]{86}$/u.test(signature))return false;
    return verify('sha256',Buffer.from(message),{key:createPublicKey({key:publicDeviceKey(key),format:'jwk'}),
      dsaEncoding:'ieee-p1363'},Buffer.from(signature,'base64url'));
  } catch{return false;}
}
export const approvalSignatureValid = (row,owner,signature) => row.owner_id===owner
  && !row.approved && Date.parse(row.challenge_expires_at)>Date.now()
  && validSignature(row.public_key,approvalMessage(owner,row.id,row.challenge),signature);

// Called only after verify-login.mjs has verified the user. Installation/UI headers grant no rights.
export async function verifyDeviceRequest(req,identity,client,{now=Date.now()}={}) {
  const h=req.headers??{},id=h['x-vault-device'],at=h['x-vault-at'],nonce=h['x-vault-nonce'];
  if(!UUID.test(id??'')||!UUID.test(nonce??'')||typeof at!=='string'||!/^[0-9]{13}$/u.test(at)
      ||Math.abs(now-Number(at))>60000||typeof req.url!=='string'||!req.url.startsWith('/api/')
      ||req.url.startsWith('//')||req.url.includes('#'))return false;
  const {data:row,error}=await client.rpc('vault_device_lookup',{p_id:id,p_owner:identity.userId});
  if(error||!row||row.id!==id||row.owner_id!==identity.userId||row.approved!==true
      ||!Number.isFinite(Date.parse(row.expires_at))||Date.parse(row.expires_at)<=now)return false;
  let body;
  try {
    body=req.body===''?undefined:typeof req.body==='string'?JSON.parse(req.body):req.body;
    if (['GET','DELETE'].includes(req.method) && (body===null || body && !Array.isArray(body)
        && typeof body==='object' && Object.keys(body).length===0)) body=undefined;
  }catch{return false;}
  const hash=digest(body===undefined?'':canonical(body));
  if(!validSignature(row.public_key,requestMessage(identity.userId,id,req.method,req.url,hash,at,nonce),h['x-vault-signature']))return false;
  const result=await client.rpc('vault_device_consume',{p_id:id,p_owner:identity.userId,p_nonce:nonce});
  return !result.error&&result.data===true;
}
