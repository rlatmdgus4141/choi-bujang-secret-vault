import { resolve } from 'node:path';
import { previewPolicy, restoreTestPolicy } from '../src/recovery-policy.mjs';
const root = resolve(import.meta.dirname, '..');
try {
  const [mode, flag, confirmation] = process.argv.slice(2);
  if (mode === 'preview') {
    const { source, ...plan } = await previewPolicy(root);
    console.log(JSON.stringify(plan, null, 2));
  } else if (mode === 'restore' && flag === '--confirm') {
    console.log(JSON.stringify(await restoreTestPolicy(root, confirmation)));
  } else throw new Error('preview 또는 restore --confirm <확인 번호>를 사용하세요');
} catch (error) { console.error('정책 복구 첫 오류:', error.message); process.exitCode = 1; }
