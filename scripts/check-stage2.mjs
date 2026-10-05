import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
// 이전 공개 커밋을 읽되 메모 본문을 현재 소스나 로그에 복사하지 않습니다.
const seed = JSON.parse(git('show', '0f9a3c9d23b9eead50b8c03ac78c8a61a7efb7fd:data.json'));
const patterns = seed.notes.map(note => note.content);
const secret = /\bsb_secret_[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{12,}\.eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}/u;
const files = [...new Set(git('ls-files', '--cached', '--others', '--exclude-standard', '-z').split('\0').filter(Boolean))];
let failures = 0;
for (const path of files) {
  const text = readFileSync(resolve(root, path), 'utf8');
  const staticMarker = ['data.json', 'public/data.json'].includes(path) && text.includes(seed.sampleMarker);
  if (patterns.some(pattern => text.includes(pattern)) || secret.test(text) || staticMarker) {
    console.error(`확인 필요: ${path}`);
    failures++;
  }
}
console.log(`현재 작업 파일 ${files.length}개: 메모 본문·비밀값 일치 ${failures}건`);
if (process.argv.includes('--deployed')) {
  const config = JSON.parse(readFileSync(resolve(root, 'aleph.config.json'), 'utf8'));
  const app = new URL(config.publicAppUrl);
  const paths = new Set(['/', '/data.json', '/aleph.json']);
  const home = await fetch(app, { redirect: 'error', signal: AbortSignal.timeout(15000) });
  const html = await home.text();
  for (const match of html.matchAll(/(?:src|href)=["']([^"']+\.(?:js|mjs|json)(?:\?[^"']*)?)["']/gu)) {
    const url = new URL(match[1], app);
    if (url.origin === app.origin) paths.add(url.pathname + url.search);
  }
  for (const path of paths) {
    const res = path === '/' ? home : await fetch(new URL(path, app), {
      redirect: 'error', signal: AbortSignal.timeout(15000),
    });
    const text = path === '/' ? html : await res.text();
    const matches = patterns.filter(pattern => text.includes(pattern)).length;
    const exposedSecret = secret.test(text);
    const staticMarker = path === '/data.json' && text.includes(seed.sampleMarker);
    console.log(`공개 정적 경로 ${path}: HTTP ${res.status}, 본문 일치 ${matches}건, 비밀값 일치 ${exposedSecret ? 1 : 0}건`);
    if (path === '/data.json') console.log(`1단계 확인 표시: ${staticMarker ? '남아 있음' : '없음'}`);
    if (!res.ok || matches || exposedSecret || staticMarker) failures++;
    if (path === '/aleph.json') {
      try {
        const identity = JSON.parse(text);
        if (identity.step !== 2 || identity.repoUrl !== config.repoUrl
            || identity.commit !== git('rev-parse', 'HEAD').trim()) failures++;
      } catch { failures++; }
    }
  }
}
if (failures) process.exitCode = 1;
