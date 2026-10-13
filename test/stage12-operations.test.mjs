import test from 'node:test';
import assert from 'node:assert/strict';
import {attachEvidence} from '../src/request-evidence.mjs';
import operations from '../api/operations.js';
import {checkOperations} from '../scripts/check-operations.mjs';
import {observation,publicProbes} from '../public/operations-protocol.js';
const response=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},status(n){this.statusCode=n;return this;},json(b){this.body=b;return this;}});
test('server evidence equals response headers, omits request payload and never accepts a client request ID',()=>{
  const res=response(),logs=[];
  attachEvidence({method:'PUT',url:'/api/notes/private-note?secret=redacted',body:{body:'private-data'},
    headers:{authorization:'sensitive-value','x-vault-request-id':'client-claimed'}},res,{VERCEL:'1'},s=>logs.push(JSON.parse(s)));
  res.status(403).json({error:'forbidden'});
  assert.equal(logs.length,1);assert.equal(logs[0].requestId,res.headers['X-Vault-Request-Id']);
  assert.equal(logs[0].checkedAt,res.headers['X-Vault-Checked-At']);assert.equal(logs[0].route,'/api/notes/:id');
  assert.equal(logs[0].status,403);assert.doesNotMatch(JSON.stringify(logs),/private-data|private-note|sensitive-value|client-claimed|secret=/);
});
test('public operations API exposes versioned software metadata only; official attacks remain unexecuted',()=>{
  const res=response();operations({method:'GET',url:'/api/operations'},res);
  assert.equal(res.statusCode,200);assert.equal(res.body.officialAttacks.total,41);assert.equal(res.body.officialAttacks.verified,0);
  assert.equal(res.body.engine.name,'ALEPH SDP 엔진');assert.equal(res.body.officialAttacks.status,'unexecuted');
  const denied=response();operations({method:'PUT',url:'/api/operations'},denied);assert.equal(denied.statusCode,405);
  assert.doesNotMatch(JSON.stringify(res.body),/owner_id|access_token|public_key|content/);
});
test('a missing evidence header or a wrong HTTP outcome is never displayed as passed',()=>{
  assert.equal(observation(publicProbes[0],Response.json({})).status,'evidence_missing');
  const h={'x-vault-request-id':'11111111-1111-4111-8111-111111111111','x-vault-checked-at':new Date().toISOString()};
  assert.equal(observation(publicProbes[0],Response.json({},{status:403,headers:h})).status,'failed');
  assert.equal(observation(publicProbes[0],Response.json({},{headers:h})).status,'passed');
});
test('same-run integration covers ownership, restore then unsigned mutation, and revoked reconnect while keeping normal reads',async()=>{
  const report=await checkOperations();assert.equal(report.passed,true);
  for(const [name,status] of [['other_owner_denied_after_anonymous_check',404],['signed_restore_after_tampering',200],
    ['unsigned_mutation_after_restore',403],['normal_read_after_restore',200],['revoked_device_reconnect_denied',403]]){
    assert.ok(report.integratedChecks.some(r=>r.name===name&&r.actual===status&&r.passed));
    const row=report.requests.find(r=>r.name===name);assert.equal(row.actual,status);assert.equal(row.expected,status);
    assert.match(row.requestId,/^[a-f0-9-]{36}$/);assert.ok(Number.isFinite(Date.parse(row.checkedAt)));
  }
  assert.equal(report.officialAttacks.verified,0);assert.equal(report.revocation.engineIdentityRevocation,'unexecuted');
  assert.doesNotMatch(JSON.stringify(report),/Bearer|owner_id|access_token|virtual only|simulated modification/);
});
