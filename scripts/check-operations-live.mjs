import {writeFile,mkdir} from 'node:fs/promises';
import config from '../aleph.config.json' with {type:'json'};
import {publicProbes,observation,unexecutedCoverage} from '../public/operations-protocol.js';
import {verifyDeployment} from './verify-deployment.mjs';
import {execFileSync} from 'node:child_process';
const commit=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim();
await verifyDeployment(config,commit);
const rows=await Promise.all(publicProbes.map(async p=>{
  const response=await fetch(new URL(p.path,config.publicAppUrl),{method:p.method,cache:'no-store',
    redirect:'error',signal:AbortSignal.timeout(15000)});
  const row=observation(p,response);await response.body?.cancel();return row;
}));
const report={schema:'aleph.operations.live.v1',commit,checkedAt:new Date().toISOString(),rows,
  unexecuted:unexecutedCoverage,officialAttacks:{total:41,verified:0,status:'unexecuted'}};
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
await writeFile(new URL('../artifacts/operations-live.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({commit,requests:rows.length,passed:rows.filter(r=>r.status==='passed').length,official41:'unexecuted'}));
if(rows.some(r=>r.status!=='passed'))process.exitCode=1;
