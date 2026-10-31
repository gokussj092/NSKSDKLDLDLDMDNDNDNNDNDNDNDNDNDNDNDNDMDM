import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm,readFile,writeFile} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {PATCH_MONTHS,TEST_HOURS,loadV2DevicePolicy,v2DevicePolicyStatus,
 changeV2DevicePolicy} from "../lib/v2-device-admission-policy.mjs";

test("strict default, explicit 1-4 year patch selector, disable both switches and automatic rollback",async()=>{
 const root=await mkdtemp(join(tmpdir(),"sp-v2-device-"));
 const now=Date.now(),config=(patchMonths,enforcePatch,enforceBoot,durationHours,expectedRevision)=>({
  patchMonths,enforcePatch,enforceBoot,durationHours,expectedRevision});
 try{
  assert.deepEqual(PATCH_MONTHS,[12,18,24,36,48]);
  assert.deepEqual(TEST_HOURS,[1,6,24,48]);
  assert.deepEqual(await v2DevicePolicyStatus({root,now}),{
   patchMonths:12,enforcePatch:true,enforceBoot:true,expiresAt:null,
   relaxed:false,revision:0,rootDetection:"not-available-via-key-attestation"});
  const accepted=await changeV2DevicePolicy(config(36,false,false,24,0),{root,now});
  assert.equal(accepted.patchMonths,36);
  assert.equal(accepted.enforcePatch,false);
  assert.equal(accepted.enforceBoot,false);
  assert.equal(accepted.relaxed,true);
  assert.equal(Date.parse(accepted.expiresAt),now+24*3600000);
  assert.equal((await loadV2DevicePolicy({root})).revision,1);
  const raw=JSON.parse(await readFile(join(root,"v2-device-admission.json"),"utf8"));
  assert.equal(raw.version,1);
  assert.equal(raw.expiresAt,now+24*3600000);
  assert.equal((await v2DevicePolicyStatus({root,now:now+23*3600000})).relaxed,true);
  const expired=await v2DevicePolicyStatus({root,now:now+24*3600000+1});
  assert.equal(expired.enforceBoot,true);
  assert.equal(expired.enforcePatch,true);
  assert.equal(expired.patchMonths,12);
  assert.equal(expired.expiresAt,null);
  assert.equal(expired.revision,1);
  await assert.rejects(changeV2DevicePolicy(config(48,true,true,1,0),{root,now}),/V2_DEVICE_POLICY_CONFLICT/);
  const reset=await changeV2DevicePolicy(config(12,true,true,24,1),{root,now});
  assert.equal(reset.relaxed,false);
  assert.equal(reset.revision,2);
  assert.equal((await loadV2DevicePolicy({root})).expiresAt,0);
 }finally{await rm(root,{recursive:true,force:true});}
});

test("validation, CAS and corrupted persistent policies fail closed",async()=>{
 const root=await mkdtemp(join(tmpdir(),"sp-v2-invalid-"));const now=Date.now();
 const cmd={patchMonths:48,enforcePatch:false,enforceBoot:false,durationHours:48,expectedRevision:0};
 try{
  await assert.rejects(changeV2DevicePolicy({...cmd,patchMonths:60},{root,now}),/V2_DEVICE_POLICY_INVALID/);
  await assert.rejects(changeV2DevicePolicy({...cmd,durationHours:72},{root,now}),/V2_DEVICE_POLICY_INVALID/);
  await assert.rejects(changeV2DevicePolicy({...cmd,enforceBoot:"false"},{root,now}),/V2_DEVICE_POLICY_INVALID/);
  const applied=await changeV2DevicePolicy(cmd,{root,now});
  assert.equal(Date.parse(applied.expiresAt),now+48*3600000);
  await writeFile(join(root,"v2-device-admission.json"),'{"enforceBoot":false,"patchMonths":48}');
  await assert.rejects(v2DevicePolicyStatus({root,now}),/V2_DEVICE_POLICY_INVALID/);
  await assert.rejects(changeV2DevicePolicy({...cmd,expectedRevision:1},{root,now}),/V2_DEVICE_POLICY_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
