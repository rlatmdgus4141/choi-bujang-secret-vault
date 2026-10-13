import { RULE_IDS } from '../src/decider.mjs';
import baseline from '../recovery/policy-baseline.json' with {type:'json'};
import { attachEvidence } from '../src/request-evidence.mjs';
export default function operations(req,res) {
  attachEvidence(req,res);
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET') { res.setHeader('Allow','GET'); return res.status(405).json({error:'method_not_allowed'}); }
  // Public software metadata only. No private device registry, note or user information.
  return res.status(200).json({schema:'aleph.operations.v1',step:12,
    commit:process.env.VERCEL_GIT_COMMIT_SHA ?? null, rules:[...RULE_IDS],
    recovery:{policyVersion:baseline.version,policySourceCommit:baseline.commit,noteBackupVersion:'stage10-v1'},
    engine:{name:'ALEPH SDP 엔진',source:'운영 측 제공',liveTelemetry:'unexecuted'},
    officialAttacks:{total:41,verified:0,status:'unexecuted',reason:'공식 41종 개별 판정 원본은 연결되지 않았습니다.'}});
}
