import {publicProbes,observation,unexecutedCoverage} from './operations-protocol.js';
const $=s=>document.querySelector(s),rows=[],status=$('#ops-status');
let metadata,report;
const scopes={live_api:'배포 API 실측',local_synthetic_api:'가상 API 연동',unexecuted:'미실행'};
const states={passed:'일치',failed:'불일치',observed:'응답 관측',unexecuted:'미실행',evidence_missing:'근거 헤더 없음',error:'연결 실패'};
function render(){
  const tbody=$('#ops-rows');tbody.replaceChildren();
  for(const row of rows.filter(r=>$('#ops-filter').value==='all'||r.scope===$('#ops-filter').value)){
    const tr=document.createElement('tr');
    for(const text of [`${row.stage} · ${row.name}`,scopes[row.scope]??row.scope,
      row.expected??'—',row.actual??'—',states[row.status]??row.status,
      `${row.requestId??'—'} / ${row.checkedAt??'—'}`]){
      const td=document.createElement('td');td.textContent=String(text);tr.append(td);
    }tbody.append(tr);
  }
  const live=rows.filter(r=>r.scope==='live_api');
  status.textContent=`배포 API ${live.length}건 관측 · 기대 일치 ${live.filter(r=>r.status==='passed').length}건 · 공식 41종 판정 미연결`;
}
function add(row){rows.push(row);if(rows.length>250)rows.splice(0,rows.length-250);render();}
window.addEventListener('vault-api-observation',event=>{
  const r=event.detail;
  // Only the already-projected observation travels to this page; no request/session/body.
  if(r?.scope==='live_api')add(r);
});
$('#ops-filter').addEventListener('change',render);
$('#ops-public').addEventListener('click',async()=>{
  $('#ops-public').disabled=true;
  await Promise.all(publicProbes.map(async p=>{
    try{const response=await fetch(p.path,{method:p.method,cache:'no-store',signal:AbortSignal.timeout(15000)});
      add(observation(p,response));await response.body?.cancel();}
    catch{add({...p,scope:'live_api',actual:null,requestId:null,checkedAt:null,status:'error'});}
  }));$('#ops-public').disabled=false;
});
$('#ops-export').addEventListener('click',()=>{
  const safe={schema:'aleph.operations.browser.v1',commit:metadata?.commit??null,rows,
    officialAttacks:metadata?.officialAttacks??{total:41,verified:0,status:'unexecuted'}};
  const url=URL.createObjectURL(new Blob([JSON.stringify(safe,null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='operations-observations.json';a.click();URL.revokeObjectURL(url);
});
try{
  const responses=await Promise.all(['/api/operations','/operations-verification.json','/aleph.json'].map(p=>fetch(p,{cache:'no-store'})));
  if(responses.some(r=>!r.ok))throw new Error('load_failed');
  [metadata,report]=await Promise.all(responses.slice(0,2).map(r=>r.json()));
  const deployment=await responses[2].json();
  if(metadata.commit!==deployment.commit||report.commit!==deployment.commit||report.schema!=='aleph.operations.verification.v1')throw new Error('commit_mismatch');
  const summary=[`검사한 배포: ${metadata.commit.slice(0,12)}`,
    `판정기: ${metadata.rules.length}개 규칙 · ${metadata.rules.join(', ')}`,
    `가상 탐지: ${report.detection.tests}건 · 의심 ${report.detection.suspiciousAction} / 정상 ${report.detection.normalAction}`,
    `회수: 가상 기기 재접속 HTTP ${report.revocation.localDeviceRevocation.actual} · 운영 신원 회수 미실행`,
    `복구: ${metadata.recovery.policyVersion} / ${metadata.recovery.noteBackupVersion} · 가상 일치 ${report.recovery.restoreMatched}`];
  for(const text of summary){const p=document.createElement('p');p.textContent=text;$('#ops-summary').append(p);}
  rows.push(...report.requests,...unexecutedCoverage.map(r=>({...r,scope:'unexecuted',status:'unexecuted',actual:null,requestId:null,checkedAt:null})));
  add(observation(publicProbes[0],responses[0]));
}catch{status.textContent='검증 정보를 확인하지 못했습니다. 배포 버전과 연결 상태를 확인하세요. 통과로 집계하지 않습니다.';}
