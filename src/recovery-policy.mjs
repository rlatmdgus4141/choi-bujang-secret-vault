import { readFile, writeFile, rename, appendFile, open, unlink } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
const SAFE_SOURCE_HASH = '1eb149a63b2f37bfbd9b55258115f9c133a4c63f473dc7639a5e7b3f3e559de0';
const SAFE_COMMIT = 'f2c660fb2241343fe2db71123d4981d6a34c10ad';
const SAFE_VERSION = '9단계 검증본';
const sha = value => createHash('sha256').update(value).digest('hex');
const paths = root => ({ backup: resolve(root, 'recovery/policy-baseline.json'),
  target: resolve(root, 'recovery/test-decider.mjs'), audit: resolve(root, 'recovery/policy-audit.log'),
  lock: resolve(root, 'recovery/policy-restore.lock'), temp: resolve(root, 'recovery/test-decider.tmp') });

export async function previewPolicy(root) {
  const p = paths(root);
  const backup = JSON.parse(await readFile(p.backup, 'utf8'));
  if (backup.schema !== 'aleph.policy.backup.v1' || backup.sourceSha256 !== SAFE_SOURCE_HASH
      || typeof backup.source !== 'string' || sha(backup.source) !== SAFE_SOURCE_HASH
      || backup.commit !== SAFE_COMMIT || backup.version !== SAFE_VERSION) throw new Error('안전 정책 사본 검증 실패');
  const current = await readFile(p.target, 'utf8');
  const before = current.split('\n'), after = backup.source.split('\n');
  const changes = [];
  for (let i = 0; i < Math.max(before.length, after.length); i++) {
    if (before[i] !== after[i]) changes.push({ line: i + 1, current: before[i] ?? null, safe: after[i] ?? null });
  }
  return { version: backup.version, backupCommit: backup.commit,
    target: 'recovery/test-decider.mjs', productionChanged: false, changes,
    confirmation: sha(SAFE_SOURCE_HASH + ':' + sha(current)), source: backup.source };
}
export async function restoreTestPolicy(root, confirmation) {
  const p = paths(root);
  const lock = await open(p.lock, 'wx');
  try {
    const plan = await previewPolicy(root);
    if (!confirmation || confirmation !== plan.confirmation) throw new Error('차이 확인 후 같은 확인 번호가 필요합니다');
    // Re-read the safe copy immediately before using it, not just during an earlier preview.
    const verified = await previewPolicy(root);
    if (verified.confirmation !== confirmation || verified.source !== plan.source) {
      throw new Error('복원 직전 사본 또는 시험 정책이 바뀌었습니다');
    }
    const record = state => JSON.stringify({ at: new Date().toISOString(), state,
      target: plan.target, backupCommit: plan.backupCommit, sourceSha256: SAFE_SOURCE_HASH });
    await writeFile(p.temp, verified.source, { flag: 'wx' });
    if (sha(await readFile(p.temp, 'utf8')) !== SAFE_SOURCE_HASH) throw new Error('복원 파일 검증 실패');
    await appendFile(p.audit, record('prepared') + '\n');
    await rename(p.temp, p.target);
    if (sha(await readFile(p.target, 'utf8')) !== SAFE_SOURCE_HASH) throw new Error('복원 후 정책 검증 실패');
    await appendFile(p.audit, record('completed') + '\n');
    return { restored: true, target: plan.target, sourceSha256: SAFE_SOURCE_HASH };
  } finally {
    await unlink(p.temp).catch(error => { if (error.code !== 'ENOENT') throw error; });
    await lock.close();
    await unlink(p.lock);
  }
}
