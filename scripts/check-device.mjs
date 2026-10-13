import {createRestoreHandler} from '../api/restore.js';
import {noteContentHash} from '../src/note-integrity.mjs';
import {generateKeyPair,SignJWT,jwtVerify} from 'jose';
import {randomUUID,webcrypto} from 'node:crypto';
import {resolve} from 'node:path';
import {createDeviceClient} from '../public/device-client.js';
import {createAuthHandler} from '../api/auth.js';
import {createDeviceHandler} from '../api/device.js';
import {createNotesHandler} from '../api/notes.js';
import config from '../aleph.config.json' with {type:'json'};

// End-to-end protocol simulation: actual browser WebCrypto client -> actual handlers -> synthetic DB.
// Keys, tokens, credentials and note contents remain in RAM and never appear in results.
export async function checkDeviceFlow({integrated=false}={}){
  const oldFetch=globalThis.fetch;
  const devices=new Map(),nonces=new Set(),grants=new Set(),notes=new Map(),snapshots=new Map(),checks=[],requests=[];
  const owner=randomUUID(),other=randomUUID(),pair=await generateKeyPair('ES256');
  const bearer=async sub=>new SignJWT({sub,iss:config.identityProvider.issuer,aud:'authenticated',role:'authenticated',
    exp:Math.floor(Date.now()/1000)+300}).setProtectedHeader({alg:'ES256'}).sign(pair.privateKey);
  const access=await bearer(owner),otherAccess=await bearer(other);
  const session={user:{id:owner},access_token:access};
  const env={SUPABASE_URL:new URL(config.identityProvider.issuer).origin,SUPABASE_SECRET_KEY:['sb','secret','fixture_device_flow'].join('_')};
  const clientFactory=()=>({auth:{async getClaims(token){try{return{data:{claims:(await jwtVerify(token,pair.publicKey)).payload}};}catch{return{error:{}};}}},
    schema(){return this;},from(table){let filters=[],fields,action='read',input;
      const execute=()=>{const data=table==='devices'?devices:notes;let matched=[...data.values()].filter(r=>filters.every(([k,v])=>r[k]===v));
        if(action==='insert'){const row={...input};data.set(row.id,row);if(table==='notes')snapshots.set(row.id,structuredClone(row));matched=[row];}
        if(action==='update')matched=matched.map(r=>{const next={...r,...input};data.set(r.id,next);return next;});
        if(action==='delete')matched.forEach(r=>data.delete(r.id));
        return{data:matched.map(r=>fields==='*'?structuredClone(r):Object.fromEntries(fields.split(',').map(k=>[k,r[k]]))),error:null};};
      return{select(v){fields=v;return this;},eq(k,v){filters.push([k,v]);return this;},insert(v){action='insert';input=v;return this;},
        update(v){action='update';input=v;return this;},delete(){action='delete';return this;},async order(){return execute();},
        async maybeSingle(){const r=execute();return{...r,data:r.data[0]??null};},async single(){return this.maybeSingle();},
        then(resolve){return Promise.resolve(execute()).then(resolve);}};},
    async rpc(name,p){
      if(name==='vault_restore_note') {
        const saved=snapshots.get(p.p_id);
        if(!saved||saved.owner_id!==p.p_owner)return{error:{code:'P0002'}};
        if(!p.p_dry_run)notes.set(saved.id,structuredClone(saved));
        return{data:{id:saved.id,owner_id:saved.owner_id,hash:noteContentHash(saved.title,saved.content),
          backupVersion:'stage10-v1',restored:!p.p_dry_run}};
      }
      if(name==='vault_device_register'){
        if(grants.has(p.p_grant_nonce))return{error:{code:'23505'}};grants.add(p.p_grant_nonce);
        devices.set(p.p_id,{id:p.p_id,owner_id:p.p_owner,public_key:p.p_key,approved:false,
          challenge:p.p_challenge,challenge_expires_at:p.p_deadline,expires_at:new Date(Date.now()+43200000).toISOString()});return{data:true};
      }
      const d=devices.get(p.p_id);
      if(name==='vault_device_lookup')return{data:d?.owner_id===p.p_owner?structuredClone(d):null};
      if(name==='vault_device_revoke'){if(d?.owner_id!==p.p_owner)return{data:false};d.approved=false;d.challenge=null;return{data:true};}
      if(name==='vault_device_confirm'){
        if(!d||d.owner_id!==p.p_owner||d.approved||d.challenge!==p.p_challenge||Date.parse(d.challenge_expires_at)<=Date.now())return{data:false};
        d.approved=true;d.challenge=null;return{data:true};
      }
      if(name==='vault_device_consume'){
        const k=p.p_id+':'+p.p_nonce;
        if(!d||d.owner_id!==p.p_owner||!d.approved||nonces.has(k))return{data:false};nonces.add(k);return{data:true};
      }
      throw new Error('unexpected_rpc');
    }});
  const auth=createAuthHandler({env,fetchImpl:async()=>Response.json({user:{id:owner},access_token:access})});
  const restore=createRestoreHandler({env,clientFactory});
  const device=createDeviceHandler({env,clientFactory}),collection=createNotesHandler({env,clientFactory}),item=createNotesHandler({env,clientFactory,itemRoute:true});
  const res=()=>({headers:{},statusCode:0,setHeader(k,v){this.headers[k]=v;},status(c){this.statusCode=c;return this;},json(b){this.body=b;return this;}});
  const transport=async(path,init={})=>{
    const r=res(),url=new URL(path,config.publicAppUrl),h=Object.fromEntries([...new Headers(init.headers)].map(([k,v])=>[k.toLowerCase(),v]));
    const req={method:init.method??'GET',url:url.pathname+url.search,headers:h,query:{},body:init.body===undefined?undefined:JSON.parse(init.body)};
    const handler=url.pathname==='/api/device'?device:url.pathname==='/api/auth'?auth:url.pathname==='/api/restore'?restore:url.pathname==='/api/notes'?collection:item;
    if(url.pathname.startsWith('/api/notes/'))req.query.id=url.pathname.slice('/api/notes/'.length);
    await handler(req,r);
    if(url.pathname!=='/api/auth') requests.push({stage:'3–11',name:'기기·자료 API 연동',method:req.method,
      path:url.pathname.startsWith('/api/notes/')?'/api/notes/:id':url.pathname,scope:'local_synthetic_api',
      expected:null,actual:r.statusCode,requestId:r.headers['X-Vault-Request-Id']??null,
      checkedAt:r.headers['X-Vault-Checked-At']??null,status:'observed'});
    return Response.json(r.body,{status:r.statusCode,headers:r.headers});
  };
  const check=(name,actual,expected)=>{if(Number.isInteger(expected)&&expected>=100&&requests.length){const row=requests.findLast(r=>r.actual===actual&&r.expected===null);if(row)Object.assign(row,{name,expected,status:actual===expected?'passed':'failed'});}const passed=actual===expected;checks.push({name,actual,expected,passed});if(!passed)throw new Error(`기기 시험 실패: ${name}`);};
  try{
    globalThis.fetch=transport;
    const app=createDeviceClient();await app.prepare();
    check('private_key_not_published',Object.keys(app).includes('privateKey'),false);
    check('data_before_approval',(await transport('/api/notes',{headers:{Authorization:`Bearer ${access}`}})).status,403);
    const login=await transport('/api/auth?authPath=token&grant_type=password',{method:'POST',
      headers:{'Content-Type':'application/json','X-Vault-Enrollment-Key':app.publicKeyHash},
      body:JSON.stringify({email:['fixture','example.invalid'].join('@'),password:'synthetic-only'})});
    check('password_login_registration_grant',login.status,200);
    app.rememberEnrollmentGrant(login.headers.get('x-vault-enrollment-grant'));
    let pending=false;
    const status=await app.approve(session,()=>{pending=true;});
    check('pending_before_confirmation',pending,true);check('server_approved',status.approved,true);
    check('approved_screen_data_request',(await app.signedFetch(session,'/api/notes')).status,200);
    const created=await app.signedFetch(session,'/api/notes',{method:'POST',body:{title:'fictional fixture',body:'virtual only'}});
    check('approved_create',created.status,201);const id=(await created.json()).id;
    check('approved_read',(await app.signedFetch(session,`/api/notes/${id}`)).status,200);
    check('approved_update',(await app.signedFetch(session,`/api/notes/${id}`,{method:'PUT',body:{title:'updated',body:'virtual only'}})).status,200);
    for(const mode of ['unsigned','path','body','user','expired']){
      globalThis.fetch=async(path,init)=>{
        const headers=new Headers(init.headers);let changedPath=path,body=init.body;
        if(mode==='unsigned')headers.delete('X-Vault-Signature');
        if(mode==='path')changedPath=`/api/notes/${randomUUID()}`;
        if(mode==='body')body=JSON.stringify({title:'changed after signing',body:'virtual only'});
        if(mode==='user')headers.set('Authorization',`Bearer ${otherAccess}`);
        if(mode==='expired')headers.set('X-Vault-At',String(Date.now()-120000));
        return transport(changedPath,{...init,headers,body});
      };
      check(mode+'_denied',(await app.signedFetch(session,`/api/notes/${id}`,{method:'PUT',body:{title:'signed fixture',body:'virtual only'}})).status,403);
    }
    globalThis.fetch=async(path,init)=>{const first=await transport(path,init);const replay=await transport(path,init);
      check('replay_denied',replay.status,403);return first;};
    check('fresh_signature_allowed',(await app.signedFetch(session,'/api/notes')).status,200);
    globalThis.fetch=transport;
    if(integrated){
      const otherId=randomUUID();notes.set(otherId,{id:otherId,owner_id:other,title:'fixture',content:'fixture'});
      check('other_owner_denied_after_anonymous_check',(await app.signedFetch(session,`/api/notes/${otherId}`)).status,404);
      notes.get(id).content='simulated modification';
      check('signed_restore_after_tampering',(await app.signedFetch(session,'/api/restore',{method:'POST',body:{id}})).status,200);
      check('restored_content_matches',notes.get(id).content===snapshots.get(id).content,true);
      check('unsigned_mutation_after_restore',(await transport(`/api/notes/${id}`,{method:'PUT',
        headers:{Authorization:`Bearer ${access}`},body:JSON.stringify({title:'fixture',body:'should not change'})})).status,403);
      check('outside_route_after_restore',(await app.signedFetch(session,'/api/notes/export')).status,400);
      check('normal_read_after_restore',(await app.signedFetch(session,`/api/notes/${id}`)).status,200);
      check('other_note_preserved',notes.get(otherId).owner_id===other,true);
    }
    let savedRequest;
    if(integrated){globalThis.fetch=async(path,init)=>{savedRequest={path,init};return Response.json({});};
      await app.signedFetch(session,'/api/notes');globalThis.fetch=transport;}
    check('approved_delete',(await app.signedFetch(session,`/api/notes/${id}`,{method:'DELETE'})).status,200);
    await app.close(session);check('client_cleared_on_logout',app.approved,false);
    check('server_revoked_on_logout',[...devices.values()].every(x=>!x.approved),true);
    if(integrated)check('revoked_device_reconnect_denied',(await transport(savedRequest.path,savedRequest.init)).status,403);
    return{schema:'aleph.device.verification.v1',scope:'local_synthetic_only',checks,requests,passed:checks.every(x=>x.passed),
      unexecuted:['live_browser_password_login_and_approval','class_engine_mtls_and_signature_attacks']};
  }finally{globalThis.fetch=oldFetch;}
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(import.meta.filename)){
  try{const r=await checkDeviceFlow();console.log(JSON.stringify({checks:r.checks.length,passed:r.passed,scope:r.scope}));}
  catch(error){console.error(error.message);process.exitCode=1;}
}
