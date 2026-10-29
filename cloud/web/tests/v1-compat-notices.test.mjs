import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readV1Protection,setV1Protection} from '../lib/v1-security-policy.mjs';
import {readNoticeState,writeNoticeState} from '../lib/notice-feed-store.mjs';

test('V1 protection is compatible by default and persists across reads',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-v1-'));
 try{
  assert.deepEqual(await readV1Protection({root,env:{}}),{enabled:false,locked:false});
  await setV1Protection(true,{root,env:{}});
  assert.deepEqual(await readV1Protection({root,env:{}}),{enabled:true,locked:false});
  assert.deepEqual(await readV1Protection({root,env:{CLOUD_V1_REQUIRE_BOUND_SESSION:'true'}}),{enabled:true,locked:true});
  await assert.rejects(setV1Protection(false,{root,env:{CLOUD_V1_REQUIRE_BOUND_SESSION:'true'}}),/V1_POLICY_LOCKED/);
  await setV1Protection(false,{root,env:{}});
  assert.equal((await readV1Protection({root,env:{}})).enabled,false);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('notice feed is private, bounded and survives read after a write',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spdecode-notices-'));
 try{
  assert.deepEqual(await readNoticeState({root}),[]);
  const records=[{id:'abc',title:'Prueba',body:'Texto'}];
  await writeNoticeState(records,{root});
  assert.deepEqual(await readNoticeState({root}),records);
  const raw=await readFile(join(root,'feed.json'),'utf8');
  assert.deepEqual(JSON.parse(raw),records);
  await assert.rejects(writeNoticeState(Array(21).fill({}),{root}),/FEED_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
