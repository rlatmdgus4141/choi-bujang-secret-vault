import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { detect, readDetectionEvents } from '../src/detect.mjs';
import { checkDetection, deviceReads } from '../scripts/detect-test.mjs';
const a = 'a'.repeat(16), b = 'b'.repeat(16);
const proposal = { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'learner_fixture', deviceId: a };
const observe = { action: 'observe' };
const withIds = rows => rows.map((row,i) => ({ ...row, requestId: `00000000-0000-4000-8000-${String(i).padStart(12,'0')}` }));

test('stage 9 passes all six official practice cases and six compound device cases', async () => {
  const results = await checkDetection(detect);
  assert.equal(results.length, 12);
  assert.ok(results.every(result => result.passed));
});

test('stage 9 projects whitelisted fields only and never retains note bodies, credentials or names', () => {
  const secret = ['sb','secret','x'.repeat(30)].join('_');
  const rows = deviceReads(121).map(row => ({ ...row, body: secret, token: secret,
    headers: { authorization: `Bearer ${secret}` }, realName: 'fixture private name' }));
  const before = JSON.stringify(rows);
  const safe = JSON.stringify(readDetectionEvents(rows));
  for (const value of [secret,'authorization','realName','fixture private name']) assert.equal(safe.includes(value), false);
  assert.deepEqual(detect(rows), proposal);
  assert.equal(JSON.stringify(rows), before);
  for (const subjectId of [secret, ['eyJabc','eyJdef','signature'].join('.'), 'name'+'@example.invalid']) {
    assert.equal(readDetectionEvents([{ ...rows[0], subjectId }]).length, 0);
  }
});

test('stage 9 uses rolling ten-minute windows, handles reverse order and excludes exactly 120 reads', () => {
  const boundary = deviceReads(121, { intervalSeconds: 5 });
  assert.deepEqual(detect(boundary), proposal);
  assert.deepEqual(detect([...boundary].reverse()), proposal);
  assert.deepEqual(detect(boundary.slice(0,120)), observe);
  const spread = [...boundary];
  spread[120] = { ...spread[120], at: new Date(Date.parse(spread[120].at) + 1).toISOString() };
  assert.deepEqual(detect(spread), observe);
  assert.deepEqual(detect(deviceReads(200, { intervalSeconds: 7 })), observe);
});

test('stage 9 never aggregates different users, devices, scopes, methods or ordinary networks', () => {
  for (const patch of [{ owner: 'different_subject' }, { deviceId: b },
    { classId: 'different_class' }, { projectId: 'different_project' }]) {
    assert.deepEqual(detect([...deviceReads(100), ...deviceReads(100, patch)]), observe);
  }
  assert.deepEqual(detect([...deviceReads(120), ...deviceReads(100).map(row => ({ ...row, method: 'POST' }))]), observe);
  assert.deepEqual(detect([...deviceReads(100), ...deviceReads(100,{ network: 'usual' })]), observe);
});

test('stage 9 requires both unfamiliar network and a valid confirmed device; one region and client headers cannot substitute', () => {
  for (const options of [{ network: 'usual', region: 'foreign' }, { network: 'unknown' },
    { source: 'none' }, { source: 'client' }, { deviceId: '' }, { deviceId: 'unverified' }, { decision: null }]) {
    assert.deepEqual(detect(deviceReads(200, options)), observe);
  }
  const rows = deviceReads(200,{ source: 'none' }).map(row => ({ ...row,
    headers: { 'x-network': 'unusual', 'x-device-id': a } }));
  assert.deepEqual(detect(rows), observe);
  assert.deepEqual(detect(deviceReads(200).map(({ signals, ...row }) => row)), observe);
  assert.deepEqual(detect(deviceReads(200).map(({ decision, ...row }) => row)), observe);
  assert.deepEqual(detect(deviceReads(121).map(({ subjectId, ...row }) => ({ ...row, identity: { sub: subjectId } }))), proposal);
  assert.deepEqual(detect(deviceReads(200).map(row => ({ ...row, identity: { sub: 'conflicting_subject' } }))), observe);
});

test('stage 9 deduplicates request IDs and discards conflicting deliveries without persistent state', () => {
  const rows = withIds(deviceReads(100));
  assert.deepEqual(detect([...rows,...rows,...rows]), observe);
  const clear = withIds(deviceReads(121));
  assert.deepEqual(detect([...clear,...clear]), proposal);
  const conflict = { ...clear[0], deviceId: b };
  assert.deepEqual(detect([...clear,conflict]), observe);
  assert.deepEqual(detect(clear), proposal);
  assert.deepEqual(detect(deviceReads(30)), observe);
});

test('stage 9 proposes one suspicious device, keeps normal device untouched and never mixes incomplete legacy events', () => {
  const rows = [...deviceReads(121), ...deviceReads(200,{ deviceId: b, network: 'usual' })];
  assert.deepEqual(detect(rows), proposal);
  const legacy = deviceReads(200).map(row => ({ at: row.at, method: row.method, identity: { sub: row.subjectId } }));
  assert.deepEqual(detect([...deviceReads(120),...legacy]), observe);
  assert.deepEqual(detect([...legacy,{ ...deviceReads(1)[0], signals: undefined }]), observe);
  assert.deepEqual(detect([]), observe);
  assert.deepEqual(detect(deviceReads(200).map(row=>({ ...row, at:'2026-02-30T00:00:00.000Z' }))), observe);
  assert.throws(() => detect(null), /invalid_detection_events/u);
});

test('stage 9 detect runs alone with no imports, I/O or Node globals', async () => {
  const source = await readFile(new URL('../src/detect.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source, /\bimport\s*(?:\(|[{'"*])/u);
  assert.doesNotMatch(source, /\b(?:fetch|eval|Function|readFile|writeFile)\s*\(/u);
  const code = `const fs=require('node:fs'),vm=require('node:vm');(async()=>{
    const context=vm.createContext({});const mod=new vm.SourceTextModule(fs.readFileSync(process.argv[1],'utf8'),{context});
    await mod.link(()=>{throw new Error('imports_forbidden')});await mod.evaluate({timeout:1000});
    context.call=mod.namespace.detect;context.events=JSON.parse(process.argv[2]);
    process.stdout.write(JSON.stringify(vm.runInContext('call(events)',context,{timeout:1000})));
  })().catch(()=>{process.exitCode=1});`;
  const out=execFileSync(process.execPath,['--experimental-vm-modules','-e',code,
    new URL('../src/detect.mjs',import.meta.url).pathname,JSON.stringify(deviceReads(121))],
    {encoding:'utf8',timeout:5000,stdio:['ignore','pipe','pipe']});
  assert.deepEqual(JSON.parse(out),proposal);
});
