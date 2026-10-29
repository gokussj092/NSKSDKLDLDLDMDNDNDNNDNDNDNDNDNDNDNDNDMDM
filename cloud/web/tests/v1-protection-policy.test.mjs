import test from "node:test";
import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {loadV1Protection,v1ProtectionRequired,v1ProtectionStatus,setV1Protection} from "../lib/v1-protection-policy.mjs";

test("V1 protection is off by default and persists only allowlisted state",async()=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-v1-policy-"));
 const env={CLOUD_V1_REQUIRE_BOUND_SESSION:"false"};
 try{
  assert.equal(await v1ProtectionRequired(env,{root}),false);
  assert.deepEqual(await setV1Protection(true,{root,env}),{enabled:true,locked:false});
  assert.equal(await v1ProtectionRequired(env,{root}),true);
  assert.deepEqual(JSON.parse(await readFile(join(root,"v1-protection.json"),"utf8")),{version:1,enabled:true});
  assert.deepEqual(await setV1Protection(false,{root,env}),{enabled:false,locked:false});
  assert.deepEqual(await loadV1Protection({root}),{version:1,enabled:false});
 }finally{await rm(root,{recursive:true,force:true});}
});
test("VPS override cannot be disabled by the panel",async()=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-v1-override-"));
 try{
  const env={CLOUD_V1_REQUIRE_BOUND_SESSION:"true"};
  assert.deepEqual(await v1ProtectionStatus(env,{root}),{enabled:true,locked:true});
  await assert.rejects(setV1Protection(false,{root,env}),/V1_POLICY_LOCKED/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test("Corrupted V1 policy fails closed",async()=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-v1-corrupt-"));
 try{
  await writeFile(join(root,"v1-protection.json"),"{bad json");
  await assert.rejects(v1ProtectionRequired({CLOUD_V1_REQUIRE_BOUND_SESSION:"false"},{root}),/V1_POLICY_INVALID/);
 }finally{await rm(root,{recursive:true,force:true});}
});
