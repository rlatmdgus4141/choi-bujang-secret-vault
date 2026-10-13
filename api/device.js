import { createClient } from '@supabase/supabase-js';
import { randomBytes, randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { UUID } from '../src/resources.mjs';
import { digest, publicDeviceKey, verifyEnrollmentGrant, approvalSignatureValid, verifyDeviceRequest } from '../src/device-access.mjs';
import { canonical } from '../public/device-protocol.js';
import config from '../aleph.config.json' with { type: 'json' };
export function createDeviceHandler({clientFactory=createClient,env=process.env}={}) {
  let runtime;
  return async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('Vary','Authorization');
    const fail=(status,error)=>res.status(status).json({error});
    if(!req.headers?.authorization)return fail(401,'유효한 로그인이 필요합니다.');
    if(env.SUPABASE_URL!==new URL(config.identityProvider.issuer).origin||!env.SUPABASE_SECRET_KEY?.startsWith('sb_secret_'))return fail(503,'서버 연결을 준비 중입니다.');
    try{
      if(!runtime){const client=clientFactory(env.SUPABASE_URL,env.SUPABASE_SECRET_KEY,{auth:{persistSession:false,autoRefreshToken:false},
        global:{fetch:(input,init)=>fetch(input,{...init,signal:AbortSignal.timeout(10000)})}});
        runtime={client,verify:createLoginVerifier({config,supabaseClient:client})};}
      const identity=await runtime.verify(req.headers.authorization);
      if(!identity)return fail(401,'유효한 로그인이 필요합니다.');
      if(req.url!=='/api/device'||Object.keys(req.query??{}).length)return fail(400,'허용되지 않은 기기 경로입니다.');
      const db=runtime.client;
      if(['GET','DELETE'].includes(req.method)){
        if(!await verifyDeviceRequest(req,identity,db))return fail(403,'서버가 승인한 기기의 서명이 필요합니다.');
        const id=req.headers['x-vault-device'];
        if(req.method==='DELETE'){
          const r=await db.rpc('vault_device_revoke',{p_id:id,p_owner:identity.userId});
          if(r.error)throw new Error('device_revoke_failed');
          return res.status(200).json({status:'revoked',approved:false});
        }
        return res.status(200).json({status:'approved',approved:true,deviceId:id});
      }
      let body;try{body=typeof req.body==='string'?JSON.parse(req.body):req.body;}catch{return fail(400,'올바른 JSON을 보내 주세요.');}
      if(req.method==='POST'){
        if(!body||Object.keys(body).some(k=>k!=='publicKey'))return fail(400,'공개 기기 키만 보내 주세요.');
        const key=publicDeviceKey(body.publicKey),hash=digest(canonical(key));
        const grant=verifyEnrollmentGrant(env.SUPABASE_SECRET_KEY,req.headers['x-vault-enrollment'],identity.userId,hash);
        if(!grant)return fail(403,'이 기기에서 비밀번호로 다시 로그인해 주세요.');
        const id=randomUUID(),challenge=randomBytes(32).toString('base64url');
        const result=await db.rpc('vault_device_register',{p_id:id,p_owner:identity.userId,p_key:key,p_grant_nonce:grant.n,
          p_challenge:challenge,p_deadline:new Date(grant.exp).toISOString()});
        if(result.error)return fail(409,'등록 요청이 만료됐거나 이미 사용됐습니다. 다시 로그인해 주세요.');
        return res.status(202).json({status:'pending',approved:false,deviceId:id,challenge});
      }
      if(req.method==='PUT'){
        if(!body||!UUID.test(body.deviceId??'')||Object.keys(body).some(k=>!['deviceId','signature'].includes(k)))return fail(400,'승인 요청을 확인해 주세요.');
        const result=await db.rpc('vault_device_lookup',{p_id:body.deviceId,p_owner:identity.userId});
        if(result.error||!result.data||!approvalSignatureValid(result.data,identity.userId,body.signature))return fail(403,'기기 확인 서명을 검증하지 못했습니다.');
        const confirmed=await db.rpc('vault_device_confirm',{p_id:body.deviceId,p_owner:identity.userId,p_challenge:result.data.challenge});
        if(confirmed.error||confirmed.data!==true)return fail(403,'승인 요청이 만료됐습니다. 다시 로그인해 주세요.');
        return res.status(200).json({status:'approved',approved:true,deviceId:body.deviceId});
      }
      res.setHeader('Allow','GET, POST, PUT, DELETE');return fail(405,'허용되지 않은 요청입니다.');
    }catch{return fail(502,'기기 승인을 확인하지 못했습니다.');}
  };
}
export default createDeviceHandler();
