import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes,scryptSync} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {loginRequest,v2DeviceAdmissionRequest} from "../lib/c6-admin-api.mjs";
import {v2DevicePolicyStatus} from "../lib/v2-device-admission-policy.mjs";
const salt=randomBytes(16),password="isolated admin v2 device policy";
Object.assign(process.env,{
 CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",CLOUD_ADMIN_USERNAME:"admin",
 CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+scryptSync(password,salt,64).toString("hex"),
 CLOUD_ADMIN_SESSION_KEY:"a".repeat(64),CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test",
 CLOUD_REDIS_URL:"redis://redis:6379"});
class Redis{
 data=new Map();counts=new Map();
 async get(k){return this.data.get(k)??null;}
 async set(k,v){this.data.set(k,v);return "OK";}
 async incr(k){const n=(this.counts.get(k)||0)+1;this.counts.set(k,n);return n;}
 async expire(){return 1;}
 async eval(_s,o){return this.incr(o.keys[0]);}
 async lPush(){} async lTrim(){}
}
function req(body,cookie="",origin="https://panel.example.test",action=true){
 return new Request("https://panel.example.test/api/admin/v2-device-admission",{
  method:"POST",headers:{Origin:origin,Cookie:cookie,"Content-Type":"application/json",
   ...(action?{"X-SPDecode-Admin-Action":"1"}:{})},body:JSON.stringify(body)});
}
test("V2 device controls require real admin, same-origin CSRF, bounded schema and revision",async()=>{
 const root=await mkdtemp(join(tmpdir(),"sp-v2-device-admin-")),redis=new Redis();
 const options={storeProvider:async()=>redis,policyOptions:{root}};
 const body={patchMonths:36,enforcePatch:true,enforceBoot:false,
  durationHours:1,expectedRevision:0,confirmation:"V2_DISPOSITIVOS_CONFIGURAR"};
 try{
  assert.equal((await v2DeviceAdmissionRequest(req(body),options)).status,401);
  const login=await loginRequest(req({username:"admin",password}),options);
  assert.equal(login.status,200);
  const cookie=login.headers.get("set-cookie").split(";")[0];
  assert.equal((await v2DeviceAdmissionRequest(req(body,cookie,"https://evil.example.test"),options)).status,403);
  assert.equal((await v2DeviceAdmissionRequest(req(body,cookie,undefined,false),options)).status,403);
  assert.equal((await v2DeviceAdmissionRequest(req({...body,extra:true},cookie),options)).status,400);
  assert.equal((await v2DeviceAdmissionRequest(req({...body,patchMonths:96},cookie),options)).status,400);
  assert.equal((await v2DeviceAdmissionRequest(req({...body,durationHours:72},cookie),options)).status,400);
  assert.equal((await v2DeviceAdmissionRequest(req({...body,confirmation:"INVALID"},cookie),options)).status,400);
  const ok=await v2DeviceAdmissionRequest(req(body,cookie),options);
  assert.equal(ok.status,200);
  const policy=(await ok.json()).v2DevicePolicy;
  assert.equal(policy.patchMonths,36);
  assert.equal(policy.enforceBoot,false);
  assert.equal(policy.enforcePatch,true);
  assert.equal(policy.revision,1);
  assert.equal((await v2DeviceAdmissionRequest(req(body,cookie),options)).status,409);
  const reset={...body,patchMonths:12,enforcePatch:true,enforceBoot:true,expectedRevision:1};
  const restored=await v2DeviceAdmissionRequest(req(reset,cookie),options);
  assert.equal(restored.status,200);
  assert.equal((await restored.json()).v2DevicePolicy.relaxed,false);
  assert.equal((await v2DevicePolicyStatus({root})).enforceBoot,true);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('permanent Play settings require authenticated admin, CSRF, exact schema and revision',async()=>{
 const {v2PlayIntegrityRequest}=await import('../lib/c6-admin-api.mjs');
 const {compatiblePlayDefaults}=await import('../lib/v2-play-policy.mjs');
 const root=await mkdtemp(join(tmpdir(),'sp-play-admin-')),redis=new Redis(),options={storeProvider:async()=>redis,policyOptions:{root}};
 const {version,revision,...settings}=compatiblePlayDefaults();
 const body={settings,expectedRevision:0,confirmation:'V2_PLAY_CONFIGURAR'};
 try{
  assert.equal((await v2PlayIntegrityRequest(req(body),options)).status,401);
  const login=await loginRequest(req({username:'admin',password}),options);
  const cookie=login.headers.get('set-cookie').split(';')[0];
  assert.equal((await v2PlayIntegrityRequest(req(body,cookie,'https://evil.example.test'),options)).status,403);
  assert.equal((await v2PlayIntegrityRequest(req({...body,settings:{...settings,requireSdk:'false'}},cookie),options)).status,400);
  const ok=await v2PlayIntegrityRequest(req(body,cookie),options);assert.equal(ok.status,200);
  const policy=(await ok.json()).v2PlayPolicy;assert.equal(policy.permanent,true);assert.equal(policy.integrityRequired,false);
  assert.equal((await v2PlayIntegrityRequest(req(body,cookie),options)).status,409);
 }finally{await rm(root,{recursive:true,force:true});}
});
