import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readStoredFeed,writeStoredFeed,noticeStorageEnabled} from '../lib/notice-store.mjs';

const env={CLOUD_NOTICE_STORE_PATH:'/app/notices/feed.json'};
test('Durable notice feed persists and reads after a simulated process restart',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-notices-'));
 try{
  assert.equal(await readStoredFeed({root,env}),null);
  const example=[{id:'123',title:'Prueba',body:'Test',createdAt:1,expiresAt:2}];
  assert.equal(await writeStoredFeed(example,{root,env}),true);
  assert.deepEqual(await readStoredFeed({root,env}),example);
  assert.deepEqual(JSON.parse(await readFile(join(root,'feed.json'),'utf8')),example);
  assert.equal(await writeStoredFeed([],{root,env}),true);
  assert.deepEqual(await readStoredFeed({root,env}),[]);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('Store fails closed on malformed or oversized data',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-notices-invalid-'));
 try{
  await writeFile(join(root,'feed.json'),'{bad json');
  await assert.rejects(readStoredFeed({root,env}),/NOTICE_STORE_INVALID/);
  await assert.rejects(writeStoredFeed(Array(21).fill({}),{root,env}),/NOTICE_STORE_INVALID/);
  assert.throws(()=>noticeStorageEnabled({CLOUD_NOTICE_STORE_PATH:'/tmp/unsafe.json'}),/NOTICE_STORE_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('Legacy unit-test mode does not access production filesystem',async()=>{
 assert.equal(noticeStorageEnabled({}),false);
 assert.equal(await readStoredFeed({env:{}}),null);
 assert.equal(await writeStoredFeed([],{env:{}}),false);
});
