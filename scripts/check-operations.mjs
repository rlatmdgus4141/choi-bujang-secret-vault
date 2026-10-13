import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {checkDeviceFlow} from './check-device.mjs';
import {checkDetection,deviceReads} from './detect-test.mjs';
import {checkRecovery} from './check-recovery.mjs';
import {detect} from '../src/detect.mjs';
import {decide,RULE_IDS} from '../src/decider.mjs';
import {fixtureRequests} from './fixture-7.mjs';
import baseline from '../recovery/policy-baseline.json' with {type:'json'};
export async function checkOperations(){
  const device=await checkDeviceFlow({integrated:true});
  const recovery=await checkRecovery();
  const detection=await checkDetection(detect);
  const {normal}=fixtureRequests();
  const decisions=[];
  for(const [name,patch,expected] of [
    ['정상 요청',{},'allow'],['미등록 기기',{deviceRegistered:false},'deny'],
    ['구역 밖 조회',{path:'/notes/export',route:'GET /notes/:id'},'deny']]){
    const requestId=randomUUID(),result=await decide({...normal,...patch,requestId});
    decisions.push({name,expected,actual:result.decision,requestId,checkedAt:new Date().toISOString(),
      scope:'local_engine_fixture',passed:result.decision===expected});
  }
  const suspicious=await detect(deviceReads(121)),usual=await detect(deviceReads(200,{network:'usual'}));
  return {schema:'aleph.operations.verification.v1',scope:'local_synthetic_only',checkedAt:new Date().toISOString(),
    rules:[...RULE_IDS],decisions,requests:device.requests,integratedChecks:device.checks,
    detection:{tests:detection.length,passed:detection.every(r=>r.passed),
      suspiciousAction:suspicious.action,normalAction:usual.action,reasonCode:suspicious.reasonCode},
    revocation:{localDeviceRevocation:device.checks.find(r=>r.name==='revoked_device_reconnect_denied'),
      engineIdentityRevocation:'unexecuted',elapsedMilliseconds:null},
    recovery:{policyVersion:baseline.version,sourceCommit:baseline.commit,noteBackupVersion:'stage10-v1',
      backupVerified:recovery.backupVerified,restoreMatched:recovery.restoreMatched,
      preservationPassed:recovery.preservationPassed,retestPassed:recovery.retestPassed},
    officialAttacks:{total:41,verified:0,status:'unexecuted'},
    passed:device.passed&&detection.every(r=>r.passed)&&decisions.every(r=>r.passed)
      &&recovery.backupVerified&&recovery.restoreMatched&&recovery.preservationPassed&&recovery.retestPassed,
    unexecuted:['official_41_attack_results','live_engine_identity_revocation','live_browser_authenticated_checks']};
}
if(process.argv[1]&&resolve(process.argv[1])===resolve(import.meta.filename)){
  const report=await checkOperations();console.log(JSON.stringify({passed:report.passed,
    integratedChecks:report.integratedChecks.length,apiResponses:report.requests.length,
    decisions:report.decisions.length,detectionTests:report.detection.tests,scope:report.scope}));
  if(!report.passed)process.exitCode=1;
}
