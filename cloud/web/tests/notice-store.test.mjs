import test from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {randomUUID} from 'node:crypto';
import {readStoredFeed,writeStoredFeed,noticeStorageEnabled,transactStoredFeed} from '../lib/notice-store.mjs';
const env={CLOUD_NOTICE_STORE_PATH:'/app/notices/feed.json'};
const notice=()=>({id:randomUUID(),title:'Prueba',body:'Aviso',createdAt:Date.now(),expiresAt:Date.now()+86400000});
test('migration persists existing Redis notices before a Redis reset; concurrent publications retain newest 20',async()=>{
 const root=await mkdtemp(join(tmpdir(),'notices-'));const options={root,env};try{
  const old=notice();let calls=0;
  const first=await transactStoredFeed(null,{...options,legacy:async()=>{calls++;return [old];}});assert.deepEqual(first.feed,[old]);
  assert.deepEqual((await transactStoredFeed(null,{...options,legacy:async()=>{throw Error('Redis reset')}})).feed,[old]);assert.equal(calls,1);
  const inputs=Array.from({length:18},notice);
  await Promise.all(inputs.map(n=>transactStoredFeed(n,options)));
  let feed=await readStoredFeed(options);assert.equal(feed.length,19);for(const n of inputs)assert(feed.some(x=>x.id===n.id));
  const same=notice();const results=await Promise.all(Array.from({length:8},()=>transactStoredFeed(same,options)));
  assert.equal(results.filter(x=>!x.duplicate).length,1);
  assert.equal((await readStoredFeed(options)).length,20);
  const fresh=notice();await transactStoredFeed(fresh,options);feed=await readStoredFeed(options);assert.equal(feed.length,20);assert(feed.some(x=>x.id===fresh.id));
  assert.equal(feed.some(x=>x.id===old.id),false);
  assert.deepEqual(JSON.parse(await readFile(join(root,'feed.json'),'utf8')),feed);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('corruption is preserved and fails closed; expiry, unknown fields, unavailable directories',async()=>{
 const root=await mkdtemp(join(tmpdir(),'notice-bad-'));const options={root,env};try{
  await writeFile(join(root,'feed.json'),'{bad');await assert.rejects(readStoredFeed(options),/NOTICE_STORE_INVALID/);
  await assert.rejects(transactStoredFeed(notice(),options));assert.equal(await readFile(join(root,'feed.json'),'utf8'),'{bad');
  await assert.rejects(writeStoredFeed([{...notice(),credentials:'never-store'}],options));
  await assert.rejects(writeStoredFeed(Array.from({length:21},notice),options));
  assert.throws(()=>noticeStorageEnabled({NODE_ENV:'production'}),/NOTICE_STORE_UNAVAILABLE/);
  assert.throws(()=>noticeStorageEnabled({CLOUD_NOTICE_STORE_PATH:'/tmp/notices'}));
  const expired={...notice(),createdAt:Date.now()-8*86400000,expiresAt:Date.now()-86400000};
  await writeStoredFeed([expired],options);assert.deepEqual((await transactStoredFeed(null,options)).feed,[]);
  await assert.rejects(transactStoredFeed(notice(),{root:join(root,'missing'),env}));
 }finally{await rm(root,{recursive:true,force:true});}
});
