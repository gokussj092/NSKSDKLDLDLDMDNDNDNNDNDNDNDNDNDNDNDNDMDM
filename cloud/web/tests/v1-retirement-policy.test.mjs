import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,rm,readFile} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {changeV1Retirement,changeV1Policy,loadV1Protection,v1PolicyStatus} from "../lib/v1-protection-policy.mjs";
import {v1Gate,nginxV1Gate} from "../lib/v1-gate.mjs";

const newRoot=()=>mkdtemp(join(tmpdir(),"spdecode-v1-retire-"));
test("V1 cutoff is durable, exactly 48 hours and effective without cron or Actions",async()=>{
 const root=await newRoot();
 try {
  const now=Date.now(),before=await v1PolicyStatus({root});
  assert.deepEqual(before,{advancedProtection:false,apiEnabled:true,revision:0});
  const scheduled=await changeV1Retirement("schedule",before.revision,{root,now});
  assert.equal(scheduled.retireAt,now+48*60*60*1000);
  assert.equal(scheduled.revision,1);
  const onDisk=JSON.parse(await readFile(join(root,"v1-protection.json"),"utf8"));
  assert.equal(onDisk.version,3);
  assert.equal(onDisk.retireAt,now+172800000);
  const active=await v1PolicyStatus({root});
  assert.equal(active.apiEnabled,true);
  assert.equal(active.retired,false);
  assert.equal((await nginxV1Gate({loadPolicy:()=>v1PolicyStatus({root})})).status,204);
  const persisted=await loadV1Protection({root});
  assert.equal(persisted.retireAt,now+172800000);
  await assert.rejects(changeV1Retirement("schedule",1,{root,now}),/V1_POLICY_CONFLICT/);
  await assert.rejects(changeV1Retirement("cancel",0,{root,now}),/V1_POLICY_CONFLICT/);
  const cancelled=await changeV1Retirement("cancel",1,{root,now});
  assert.deepEqual(cancelled,{advancedProtection:false,apiEnabled:true,revision:2});
  assert.equal((await loadV1Protection({root})).version,2);
 } finally {await rm(root,{recursive:true,force:true});}
});

test("past cutoff automatically blocks all V1 methods and Nginx while V2/admin stay untouched",async()=>{
 const root=await newRoot();
 try {
  // Simulate a schedule confirmed 49h earlier, without waiting or timers.
  const old=Date.now()-49*3600000;
  await changeV1Retirement("schedule",0,{root,now:old});
  const p=await v1PolicyStatus({root});
  assert.equal(p.apiEnabled,false);
  assert.equal(p.retired,true);
  assert.equal((await nginxV1Gate({loadPolicy:()=>v1PolicyStatus({root})})).status,403);
  for(const method of ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]){
   for(const path of ["/api/v1","/api/v1/health","/api/v1/session","/api/v1/decode/file","/api/v1/whats-new"]){
    const res=await v1Gate(new Request("https://api.example.test"+path,{method}),
      {loadPolicy:()=>v1PolicyStatus({root})});
    assert.equal(res?.status,410,method+" "+path);
    assert.equal((await res.json()).error.code,"V1_API_DISABLED");
   }
  }
  for(const path of ["/api/v2/transport","/api/admin/session","/admin/api-v1","/api/health/live"]){
   assert.equal(await v1Gate(new Request("https://example.test"+path),
    {loadPolicy:()=>v1PolicyStatus({root})}),undefined);
  }
  const cancelled=await changeV1Retirement("cancel",1,{root});
  assert.equal(cancelled.apiEnabled,true);
  assert.equal((await v1PolicyStatus({root})).apiEnabled,true);
 } finally {await rm(root,{recursive:true,force:true});}
});

test("retirement cannot be scheduled on a disabled V1 API; corrupt persistent schedule fails closed",async()=>{
 const root=await newRoot();
 try {
  const disabled=await changeV1Policy("apiEnabled",false,0,{root});
  assert.equal(disabled.apiEnabled,false);
  await assert.rejects(changeV1Retirement("schedule",disabled.revision,{root}),/V1_POLICY_CONFLICT/);
  await assert.rejects(changeV1Retirement("cancel",disabled.revision,{root}),/V1_POLICY_CONFLICT/);
  await assert.rejects(changeV1Retirement("schedule",-1,{root}),/V1_POLICY_INVALID/);
 } finally {await rm(root,{recursive:true,force:true});}
});
