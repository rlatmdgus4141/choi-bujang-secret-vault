import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {checkDeviceFlow} from '../scripts/check-device.mjs';
import {issueEnrollmentGrant,verifyEnrollmentGrant} from '../src/device-access.mjs';
test('actual WebCrypto client, approval server and protected API preserve normal CRUD and deny unsigned/tampered requests',async()=>{
  const r=await checkDeviceFlow();assert.equal(r.passed,true);assert.ok(r.checks.length>=18);
  for(const name of ['data_before_approval','unsigned_denied','path_denied','body_denied','user_denied','replay_denied']){
    assert.ok(r.checks.some(x=>x.name===name&&x.actual===403));
  }
  assert.equal(JSON.stringify(r).includes('Bearer'),false);
});
test('enrollment requires server-issued password-login permission bound to owner/key and an unexpired MAC',()=>{
  const secret=['sb','secret','fixture_permission'].join('_'),owner=randomUUID(),h='a'.repeat(64),now=Date.now();
  const g=issueEnrollmentGrant(secret,owner,h,now);
  assert.ok(verifyEnrollmentGrant(secret,g,owner,h,now));
  for(const [grant,user,hash,time]of[[g,randomUUID(),h,now],[g,owner,'b'.repeat(64),now],
    [g,owner,h,now+180001],[g.slice(0,-2)+'aa',owner,h,now]])assert.equal(verifyEnrollmentGrant(secret,grant,user,hash,time),null);
});
test('PWA has real installation assets; private requests and session/device material never enter persistent caches',async()=>{
  const manifest=JSON.parse(await readFile(new URL('../public/manifest.webmanifest',import.meta.url),'utf8'));
  assert.equal(manifest.start_url,'/');assert.equal(manifest.display,'standalone');assert.equal(manifest.icons.length,2);
  for(const i of manifest.icons){const bytes=await readFile(new URL('..'+i.src.replace('/icons/','/public/icons/'),import.meta.url));assert.equal(bytes.subarray(1,4).toString(),'PNG');}
  const [auth,client,sw,pwa]=await Promise.all(['auth.js','device-client.js','sw.js','pwa.js'].map(f=>readFile(new URL('../public/'+f,import.meta.url),'utf8')));
  assert.match(auth,/persistSession: false/u);
  assert.doesNotMatch(auth+client,/localStorage\.setItem|sessionStorage\.setItem|indexedDB\.open|exportKey\([^\n]*privateKey/u);
  assert.match(sw,/url\.pathname\.startsWith\('\/api\/'\)\) return/u);
  assert.doesNotMatch(sw,/cache\.put/u);assert.doesNotMatch(pwa,/approved\s*=\s*true/u);
});
