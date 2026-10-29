import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readPersistedNotices,writePersistedNotices} from '../lib/notice-feed-store.mjs';
import {legacyProtectionStatus,setLegacyProtection} from '../lib/v1-compat-policy.mjs';

test('notice feed persists independently of the ephemeral Redis process',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spnotice-test-'));
 try{
  assert.deepEqual(await readPersistedNotices(root),[]);
  const item={id:'00000000-0000-4000-8000-000000000001',title:'Test',body:'Hello',createdAt:1,expiresAt:2};
  await writePersistedNotices([item],root);
  assert.deepEqual(await readPersistedNotices(root),[item]);
  await assert.rejects(writePersistedNotices(Array(21).fill(item),root),/FEED_INVALID/);
  await writeFile(join(root,'notices.json'),'INVALID');
  await assert.rejects(readPersistedNotices(root));
 }finally{await rm(root,{recursive:true,force:true});}
});
test('strict V1 policy persists and VPS override cannot be disabled in panel',async()=>{
 const root=await mkdtemp(join(tmpdir(),'spv1-test-'));
 try{
  const env={CLOUD_V1_REQUIRE_BOUND_SESSION:'false'};
  assert.deepEqual(await legacyProtectionStatus(env,{root}),{strict:false,locked:false});
  await setLegacyProtection(true,env,{root,v2Ready:true});
  assert.deepEqual(await legacyProtectionStatus(env,{root}),{strict:true,locked:false});
  await setLegacyProtection(false,env,{root,v2Ready:true});
  assert.deepEqual(await legacyProtectionStatus(env,{root}),{strict:false,locked:false});
  await assert.rejects(setLegacyProtection(true,env,{root,v2Ready:false}),/V2_NOT_CONFIGURED/);
  assert.deepEqual(await legacyProtectionStatus({CLOUD_V1_REQUIRE_BOUND_SESSION:'true'},{root}),{strict:true,locked:true});
  await assert.rejects(setLegacyProtection(false,{CLOUD_V1_REQUIRE_BOUND_SESSION:'true'},{root,v2Ready:true}),/V1_POLICY_LOCKED/);
  await writeFile(join(root,'v1-security.json'),'{"strict":"yes","updatedAt":"fake"}');
  await assert.rejects(legacyProtectionStatus(env,{root}),/V1_POLICY_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
