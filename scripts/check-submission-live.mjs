// Real public deployment checks, separate from stage 12 submission observations.
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import config from '../aleph.config.json' with { type: 'json' };
import { runLiveAttackChecks } from '../src/attack-check.mjs';
import { verifyDeployment } from './verify-deployment.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
await verifyDeployment(config, commit);
const attackAttempts = await runLiveAttackChecks(config, { requirePass: true });
const report = { schema: 'aleph.deployment.self-check.v1', commit,
  checkedAt: new Date().toISOString(), scope: 'student_public_self_check', attackAttempts,
  officialAttacks: { total: 41, verified: 0, status: 'unexecuted' } };
mkdirSync(fileURLToPath(new URL('../artifacts/', import.meta.url)), { recursive: true });
writeFileSync(fileURLToPath(new URL('../artifacts/deployment-self-check.json', import.meta.url)),
  JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ commit, executed: attackAttempts.filter(item => item.observed !== 'not_run').length,
  notRun: attackAttempts.filter(item => item.observed === 'not_run').length,
  official41: 'unexecuted', output: 'artifacts/deployment-self-check.json' }));
