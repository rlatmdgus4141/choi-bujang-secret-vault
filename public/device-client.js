import {canonical,requestMessage,approvalMessage} from './device-protocol.js';
const encode=new TextEncoder();
const hex=bytes=>[...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');
const hash=async value=>hex(await crypto.subtle.digest('SHA-256',encode.encode(value)));
const base64url=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/u,'');
export function createDeviceClient(){
  let pair=null,key=null,keyHash=null,grant=null,id=null,approved=false;
  const reset=()=>{pair=null;key=null;keyHash=null;grant=null;id=null;approved=false;};
  const sign=async message=>base64url(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,encode.encode(message)));
  const decode=async response=>{const value=await response.json();if(!response.ok){const error=new Error('device_request_failed');error.status=response.status;throw error;}return value;};
  async function prepare(){
    reset();pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
    const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);
    key={kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y};keyHash=await hash(canonical(key));
  }
  async function signedFetch(session,path,{method='GET',body,signal,allowPending=false}={}){
    if(!pair||!id||!approved&&!allowPending){const error=new Error('device_not_approved');error.status=403;throw error;}
    if(!path.startsWith('/api/')||path.startsWith('//'))throw new Error('invalid_device_path');
    const at=String(Date.now()),nonce=crypto.randomUUID(),bodyHash=await hash(body===undefined?'':canonical(body));
    const signature=await sign(requestMessage(session.user.id,id,method,path,bodyHash,at,nonce));
    return fetch(path,{method,signal,cache:'no-store',headers:{Authorization:`Bearer ${session.access_token}`,
      'X-Vault-Device':id,'X-Vault-At':at,'X-Vault-Nonce':nonce,'X-Vault-Signature':signature,
      ...(body===undefined?{}:{'Content-Type':'application/json'})},...(body===undefined?{}:{body:JSON.stringify(body)})});
  }
  async function approve(session,onPending=()=>{}){
    if(!pair||!grant)throw new Error('fresh_login_required');
    const pending=await decode(await fetch('/api/device',{method:'POST',cache:'no-store',
      headers:{Authorization:`Bearer ${session.access_token}`,'X-Vault-Enrollment':grant,'Content-Type':'application/json'},
      body:JSON.stringify({publicKey:key})}));
    grant=null;id=pending.deviceId;
    if(pending.status!=='pending'||pending.approved!==false||typeof pending.challenge!=='string')throw new Error('invalid_device_response');
    onPending();
    const confirmed=await decode(await fetch('/api/device',{method:'PUT',cache:'no-store',
      headers:{Authorization:`Bearer ${session.access_token}`,'Content-Type':'application/json'},
      body:JSON.stringify({deviceId:id,signature:await sign(approvalMessage(session.user.id,id,pending.challenge))})}));
    if(confirmed.approved!==true||confirmed.deviceId!==id)throw new Error('device_not_approved');
    const status=await decode(await signedFetch(session,'/api/device',{allowPending:true}));
    approved=status.approved===true&&status.status==='approved'&&status.deviceId===id;
    if(!approved)throw new Error('device_not_approved');return status;
  }
  async function close(session){try{if(approved&&session)await signedFetch(session,'/api/device',{method:'DELETE'});}finally{reset();}}
  return {prepare,approve,signedFetch,close,reset,get publicKeyHash(){return keyHash;},get approved(){return approved;},
    rememberEnrollmentGrant(value){grant=value||null;}};
}
