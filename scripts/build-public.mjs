import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const source = resolve(root, 'data.json');
const output = resolve(root, 'public', 'data.json');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
if (![1, 2, 3, 4].includes(config.step)) {
  throw new Error('현재 구현된 자료실 단계는 1~4단계입니다.');
}
const data = JSON.parse(await readFile(source, 'utf8'));
if (!Array.isArray(data.notes)) {
  throw new Error('실습용 공개 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.');
}
if (config.step >= 2 && (data.notes.length !== 0
    || Object.keys(data).some(key => key !== 'notes'))) {
  throw new Error('2단계 이후 data.json에는 빈 notes 배열만 둘 수 있습니다. 1단계 확인 표시도 제거하세요.');
}
await mkdir(resolve(root, 'public'), { recursive: true });
await copyFile(source, output);
// package-lock.json에 고정된 공식 SDK만 브라우저에 제공합니다.
await mkdir(resolve(root, 'public/vendor'), { recursive: true });
await copyFile(resolve(root, 'node_modules/@supabase/supabase-js/dist/umd/supabase.js'),
  resolve(root, 'public/vendor/supabase.js'));
await copyFile(resolve(root, 'node_modules/@supabase/supabase-js/LICENSE'),
  resolve(root, 'public/vendor/supabase-LICENSE.txt'));
console.log(config.step >= 2 ? '메모가 없는 public/data.json을 생성했습니다.'
  : '실습용 공개 자료를 public/data.json에 복사했습니다.');
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`, 'utf8');
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
