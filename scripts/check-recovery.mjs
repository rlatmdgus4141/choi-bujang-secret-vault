import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { generateKeyPair, SignJWT, jwtVerify } from 'jose';
import { previewPolicy, restoreTestPolicy } from '../src/recovery-policy.mjs';
import { createNotesHandler } from '../api/notes.js';
import { createNoticesHandler } from '../api/notices.js';
import { checkDetection } from './detect-test.mjs';
import { detect } from '../src/detect.mjs';
import { fixtureRequests } from './fixture-7.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const root = resolve(import.meta.dirname, '..');
const hash = source => createHash('sha256').update(source).digest('hex');
const response = () => ({ headers: {}, statusCode: 0, body: null,
  setHeader(k,v) { this.headers[k]=v; }, status(code) { this.statusCode=code; return this; },
  json(body) { this.body=body; return this; } });

// Only synthetic accounts/notes and RAM signing keys are used here. No live user tokens or DB rows.
async function apiRetest() {
  const pair = await generateKeyPair('ES256'), wrong = await generateKeyPair('ES256');
  const a = randomUUID(), b = randomUUID(), rows = new Map(), checks = [];
  const env = { SUPABASE_URL: new URL(config.identityProvider.issuer).origin,
    SUPABASE_SECRET_KEY: ['sb','secret','fixture'].join('_') };
  const token = async (sub, patch = {}, key = pair.privateKey) => `Bearer ${await new SignJWT({
    iss: config.identityProvider.issuer, aud: 'authenticated', sub, role: 'authenticated',
    exp: Math.floor(Date.now()/1000)+300, ...patch,
  }).setProtectedHeader({ alg: 'ES256' }).sign(key)}`;
  const clientFactory = () => ({ auth: {
    async getClaims(value) {
      try { return { data: { claims: (await jwtVerify(value, pair.publicKey)).payload } }; }
      catch { return { data: null, error: {} }; }
    }, admin: { async getUserById(id) { return { data: { user: { id, app_metadata: {} } } }; } },
  }, from() {
    let action='read', input, fields='id', filters=[];
    const execute = () => {
      let matched = [...rows.values()].filter(row=>filters.every(([k,v])=>row[k]===v));
      if(action==='insert') {
        if(rows.has(input.id)) return { data:null,error:{code:'23505'} };
        const row={...input,position:rows.size+1}; rows.set(row.id,row); matched=[row];
      } else if(action==='update') matched=matched.map(row=>{
        const next={...row,...input};rows.set(row.id,next);return next;
      });
      else if(action==='delete') matched.forEach(row=>rows.delete(row.id));
      return {data:matched.map(row=>Object.fromEntries(fields.split(',').map(k=>[k,row[k]]))),error:null};
    };
    return { select(f){fields=f;return this;},insert(v){action='insert';input=v;return this;},
      update(v){action='update';input=v;return this;},delete(){action='delete';return this;},
      eq(k,v){filters.push([k,v]);return this;},async order(){return execute();},
      async maybeSingle(){const r=execute();return {...r,data:r.data?.[0]??null};},async single(){return this.maybeSingle();} };
  } });
  const collection=createNotesHandler({env,clientFactory}), item=createNotesHandler({env,clientFactory,itemRoute:true});
  const notice=createNoticesHandler({env,clientFactory,itemRoute:true});
  const call=async(method,bearer,body,id)=>{
    const res=response();await(id?item:collection)({method,headers:{authorization:bearer},body,
      url:id?`/api/notes/${id}`:'/api/notes',query:id?{id}:{}},res);return res;
  };
  const check=(name,actual,expected)=>{
    const passed=actual===expected;checks.push({name,expected,actual,passed});
    if(!passed)throw new Error(`복원 뒤 API 재시험 실패: ${name}`);
  };
  const ta=await token(a),tb=await token(b),ids=[];
  for(const [label,bearer]of[['A',ta],['B',tb]]) {
    const created=await call('POST',bearer,{title:'synthetic fixture',body:'fictional only'});
    check(`${label}_own_create`,created.statusCode,201);ids.push(created.body.id);
  }
  // A verified pre-incident snapshot is held in RAM, then B is corrupted and restored before API retests.
  const saved=structuredClone(rows.get(ids[1]));const savedHash=hash(JSON.stringify(saved));
  rows.set(ids[1],{...saved,title:'synthetic corruption'});
  if(hash(JSON.stringify(saved))!==savedHash)throw new Error('모의 메모 사본 검증 실패');
  rows.set(saved.id,structuredClone(saved));
  check('B_restored_snapshot_hash',hash(JSON.stringify(rows.get(saved.id))),savedHash);
  for(let i=0;i<2;i++) {
    const label=i===0?'A':'B',bearer=i===0?ta:tb,own=ids[i],other=ids[1-i];
    const list=await call('GET',bearer);check(`${label}_own_list`,list.statusCode,200);
    check(`${label}_list_scope`,JSON.stringify(list.body.map(x=>x.id)),JSON.stringify([own]));
    check(`${label}_own_read`,(await call('GET',bearer,undefined,own)).statusCode,200);
    check(`${label}_own_update`,(await call('PUT',bearer,{title:'updated fake note',body:'fictional only'},own)).statusCode,200);
    for(const method of ['GET','PUT','DELETE'])check(`${label}_other_${method}`,
      (await call(method,bearer,{title:'foreign change',body:''},other)).statusCode,404);
    check(`${label}_owner_change`,(await call('PUT',bearer,{title:'fake',body:'',owner_id:i===0?b:a},own)).statusCode,403);
  }
  for(const method of ['GET','POST','PUT','DELETE'])check(`anonymous_${method}`,
    (await call(method,undefined,{title:'fake',body:''},['PUT','DELETE'].includes(method)?ids[0]:undefined)).statusCode,401);
  for(const [name,bearer] of [
    ['forged',await token(a,{},wrong.privateKey)],['expired',await token(a,{exp:1})],
    ['other_audience',await token(a,{aud:'other-service'})],['other_issuer',await token(a,{iss:'https://other.supabase.co/auth/v1'})],
  ])check(`token_${name}`,(await call('GET',bearer)).statusCode,401);
  const denied=response();await notice({method:'PUT',url:`/api/notices/${randomUUID()}`,query:{},
    headers:{authorization:ta},body:{title:'fake',body:'',role:'instructor'}},denied);
  check('student_notice_write',denied.statusCode,403);
  for(const [i,bearer] of [ta,tb].entries()){
    check(`${i===0?'A':'B'}_own_delete`,(await call('DELETE',bearer,undefined,ids[i])).statusCode,200);
    check(`${i===0?'A':'B'}_deleted_read`,(await call('GET',bearer,undefined,ids[i])).statusCode,404);
  }
  return checks;
}

export async function checkRecovery({ projectRoot=root } = {}) {
  const sandbox=await mkdtemp(join(tmpdir(),'vault-restore-check-'));
  const checks=[];
  const add=(name,passed)=>{checks.push({name,passed});if(!passed)throw new Error(`복구 점검 실패: ${name}`);};
  try {
    await mkdir(join(sandbox,'recovery'));
    const raw=await readFile(join(projectRoot,'recovery/policy-baseline.json'),'utf8');
    const baseline=JSON.parse(raw),target=join(sandbox,'recovery/test-decider.mjs'),backup=join(sandbox,'recovery/policy-baseline.json');
    await writeFile(backup,raw);await writeFile(target,baseline.source);
    await writeFile(join(sandbox,'recovery/policy-audit.log'),'existing audit\n');
    await writeFile(join(sandbox,'other-policy.json'),'preserve other service');
    const first=await previewPolicy(sandbox);
    add('backup_re_read_hash_verified',first.source===baseline.source&&hash(first.source)===baseline.sourceSha256);
    const corrupted=baseline.source.replace("return reply('deny', 'device_not_registered'", "return reply('allow', 'device_not_registered'");
    await writeFile(target,corrupted);
    const plan=await previewPolicy(sandbox);
    add('restore_version_and_changes_previewed',plan.backupCommit===baseline.commit&&plan.version===baseline.version&&plan.changes.length>0&&!plan.productionChanged);
    const auditBefore=await readFile(join(sandbox,'recovery/policy-audit.log'),'utf8');
    const rejected=async name=>{
      let failed=false;try{await restoreTestPolicy(sandbox,plan.confirmation);}catch{failed=true;}
      add(name,failed&&(await readFile(target,'utf8'))===corrupted&&(await readFile(join(sandbox,'recovery/policy-audit.log'),'utf8'))===auditBefore);
    };
    await writeFile(backup,JSON.stringify({...baseline,source:baseline.source+'corrupt'}));
    await rejected('invalid_backup_stops_before_write');
    await rm(backup);await rejected('missing_backup_stops_before_write');
    await writeFile(backup,raw);
    await restoreTestPolicy(sandbox,plan.confirmation);
    const restored=await readFile(target,'utf8');add('restored_policy_re_read_verified',hash(restored)===baseline.sourceSha256);
    add('other_policy_and_old_audit_preserved',(await readFile(join(sandbox,'other-policy.json'),'utf8'))==='preserve other service'
      &&(await readFile(join(sandbox,'recovery/policy-audit.log'),'utf8')).startsWith(auditBefore));
    // Load the restored file only AFTER restoring and reading its checksum again.
    const {decide}=await import(pathToFileURL(target).href);
    const {normal,suspicious}=fixtureRequests();
    const policyChecks=[
      ['registered_normal',normal,'allow'],['unregistered',{...normal,deviceRegistered:false},'deny'],
      ['compound_risk',suspicious,'step_up'],['fresh_step_up',{...suspicious,stepUp:{verified:true,authAgeSeconds:60}},'allow'],
      ['global_note_list',{...normal,path:'/notes',route:'GET /notes'},'deny'],
      ['notice_write',{...normal,service:'notices',method:'PUT',path:'/notices/demo',route:'PUT /notices/:id'},'deny'],
    ];
    const retests=[];
    for(const[name,input,expected]of policyChecks){const actual=(await decide(input)).decision;
      retests.push({name,expected,actual,passed:actual===expected});if(actual!==expected)throw new Error(`복원 뒤 판정 재시험 실패: ${name}`);}
    const detection=await checkDetection(detect);
    retests.push({name:'detection_12_cases',expected:12,actual:detection.filter(x=>x.passed).length,passed:detection.every(x=>x.passed)});
    if(!detection.every(x=>x.passed))throw new Error('복원 뒤 탐지 재시험 실패');
    retests.push(...await apiRetest());
    const sources={};
    for(const file of ['src/recovery-policy.mjs','scripts/check-recovery.mjs','src/verify-login.mjs','src/decider.mjs','src/detect.mjs','api/notes.js','api/notices.js']) {
      sources[file]=hash(await readFile(join(projectRoot,file)));
    }
    return {schema:'aleph.recovery.verification.v1',executedAt:new Date().toISOString(),
      command:'npm run recovery:check',scope:'local_synthetic_only',backupVersion:baseline.version,
      backupCommit:baseline.commit,backupHash:baseline.sourceSha256,checks,retests,sources,
      backupVerified:checks.every(x=>x.passed),retestPassed:retests.every(x=>x.passed),
      unexecuted:['live_browser_B_restore','engine_revocation_and_timing'],productionPolicyChanged:false};
  } finally {await rm(sandbox,{recursive:true,force:true});}
}

if(process.argv[1]&&resolve(process.argv[1])===resolve(import.meta.filename)) {
  try {
    const report=await checkRecovery();
    if(process.argv.includes('--write'))await writeFile(join(root,'recovery/verification.json'),JSON.stringify(report,null,2)+'\n');
    console.log(JSON.stringify({backupVerified:report.backupVerified,retestPassed:report.retestPassed,
      backupChecks:report.checks.length,retests:report.retests.length,scope:report.scope}));
  } catch(error){console.error('복구 점검 첫 오류:',error.message);process.exitCode=1;}
}
