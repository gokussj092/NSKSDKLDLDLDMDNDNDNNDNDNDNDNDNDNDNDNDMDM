import assert from "node:assert/strict";
import {test} from "node:test";
import {randomBytes,scryptSync} from "node:crypto";
import {adminLogin} from "../lib/c6-admin-auth.mjs";
import {resetErrorsRequest} from "../lib/c6-admin-api.mjs";
import {recordWorkerResult,usageReport,resetErrorBaselines,classifyWorkerOutcome} from "../lib/c6-ops-store.mjs";
import {readIncidents} from "../lib/c9-diagnostics.mjs";

class FakeRedis{
 constructor(){this.strings=new Map();this.hashes=new Map();this.counters=new Map();this.lists=new Map();}
 async get(k){return this.strings.get(k)??null;}
 async set(k,v,opts={}){if(opts.NX&&this.strings.has(k))return null;this.strings.set(k,v);return "OK";}
 async eval(script,opts){if(script.includes("spdecode:throttle:v1"))return this.incr(opts.keys[0]);throw Error("Unsupported Lua");}
  async incr(k){const n=(this.counters.get(k)||0)+1;this.counters.set(k,n);return n;}
 async mGet(keys){return keys.map(k=>String(this.counters.get(k)||0));}
 async expire(){return 1;}
 async hGetAll(k){return this.hashes.get(k)||{};}
 async hSet(k,field,value){const h=this.hashes.get(k)||{};h[field]=value;this.hashes.set(k,h);return 1;}
 async hIncrBy(k,field,amount){const h=this.hashes.get(k)||{};h[field]=(h[field]||0)+amount;this.hashes.set(k,h);return h[field];}
 async lPush(k,v){this.lists.set(k,[v,...(this.lists.get(k)||[])]);return this.lists.get(k).length;}
 async lTrim(k,start,stop){this.lists.set(k,(this.lists.get(k)||[]).slice(start,stop+1));}
 async lRange(k,start,stop){return (this.lists.get(k)||[]).slice(start,stop+1);}
 multi(){
  const commands=[],api={};
  for(const method of ["incr","hIncrBy","hSet","expire"]){
   api[method]=(...args)=>{commands.push([method,...args]);return api;};
  }
  api.exec=async()=>{for(const [method,...args] of commands)await this[method](...args);return [];};
  return api;
 }
}
test("HTTP Custom missing password/HWID, user cancellation are not error operations",async()=>{
 const r=new FakeRedis();
 for(const code of ["PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED","CANCELLED"]){
  assert.equal(classifyWorkerOutcome("failed",{kind:"file",format:"hc",errorCode:code}),"ignored");
  await recordWorkerResult(r,"failed",{kind:"file",format:"hc",errorCode:code});
 }
 const report=await usageReport(r,7);
 assert.equal(report.totalDecodes,0);
 assert.equal(report.failedDecodes,0);
 assert.equal((await readIncidents(r,7)).length,0);
});
test("unsupported formats and NPVS decoding incompatibility are warnings, not backend failures",async()=>{
 const r=new FakeRedis();
 await recordWorkerResult(r,"failed",{kind:"file",format:"npvs",bytes:30,errorCode:"DECODE_FAILED"});
 await recordWorkerResult(r,"failed",{kind:"file",format:"npvs",bytes:20,errorCode:"UNSUPPORTED_FORMAT"});
 await recordWorkerResult(r,"failed",{kind:"file",format:"hc",bytes:10,errorCode:"UNSUPPORTED_VERSION"});
 const report=await usageReport(r,7);
 assert.equal(report.failedDecodes,0);
 assert.equal(report.warnings,3);
 assert.equal(report.extensions.find(x=>x.extension==="npvs").warnings,2);
 assert.equal(report.errors.length,0);
 // Only the ambiguous DECODE_FAILED remains reportable; known incompatibilities are expected, not incidents.
 assert.equal((await readIncidents(r,7)).filter(x=>x.severity==="warning").length,1);
});
test("reset a single VPN provider's errors, preserving successes, other errors and warnings",async()=>{
 const r=new FakeRedis();
 const vpn=(errorCode)=>recordWorkerResult(r,"failed",{kind:"server-vpn",format:"mkk-hyper",bytes:10,errorCode});
 await recordWorkerResult(r,"success",{kind:"server-vpn",format:"mkk-hyper",bytes:100});
 await vpn("ENGINE_TIMEOUT");
 await recordWorkerResult(r,"failed",{kind:"server-vpn",format:"nur-tunnel",bytes:2,errorCode:"ENGINE_UNAVAILABLE"});
 await recordWorkerResult(r,"failed",{kind:"file",format:"npvs",errorCode:"DECODE_FAILED"});
 const before=await usageReport(r,7);
 assert.equal(before.failedDecodes,2);
 assert.equal(before.warnings,1);
 const reset=await resetErrorBaselines(r,{scope:"format",format:"vpn-mkk-hyper"});
 assert.equal(reset.formatsReset,1);
 const after=await usageReport(r,7);
 assert.equal(after.successfulDecodes,1);
 assert.equal(after.failedDecodes,1);
 assert.equal(after.totalDecodes,before.totalDecodes);
 assert.equal(after.serviceBreakdown.find(x=>x.service==="serverVpn").attempts,
   before.serviceBreakdown.find(x=>x.service==="serverVpn").attempts);
 assert.equal(after.warnings,1);
 assert.equal(after.extensions.find(x=>x.extension==="vpn-mkk-hyper").attempts,2);
 assert.equal(after.extensions.find(x=>x.extension==="vpn-mkk-hyper").failedDecodes,0);
 assert.ok(!after.errors.some(x=>x.code==="ENGINE_TIMEOUT"));
 assert.ok((await readIncidents(r,7,Object.fromEntries(
  after.resets.map(x=>[x.extension,{at:x.at}])))).every(x=>x.format!=="mkk-hyper"));
 await vpn("ENGINE_TIMEOUT");
 const latest=await usageReport(r,7);
 assert.equal(latest.failedDecodes,2);
 assert.equal(latest.extensions.find(x=>x.extension==="vpn-mkk-hyper").failedDecodes,1);
 const all=await resetErrorBaselines(r,{scope:"all"});
 assert.equal(all.formatsReset,3);
 assert.equal((await usageReport(r,7)).failedDecodes,0);
 await recordWorkerResult(r,"failed",{kind:"file",format:"hc",errorCode:"ENGINE_TIMEOUT"});
 assert.equal((await usageReport(r,7)).failedDecodes,1);
});
test("reset endpoint is authenticated, CSRF protected, allowlisted and never erases success",async()=>{
 const salt=randomBytes(16),password="strict administrative password reset tests";
 Object.assign(process.env,{
  CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",CLOUD_ADMIN_USERNAME:"operator",
  CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+
   scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex"),
  CLOUD_ADMIN_SESSION_KEY:"z".repeat(64),
  CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test",
  CLOUD_REDIS_URL:"redis://redis:6379"
 });
 const redis=new FakeRedis(),options={storeProvider:async()=>redis};
 await recordWorkerResult(redis,"success",{kind:"file",format:"hc",bytes:200});
 await recordWorkerResult(redis,"failed",{kind:"file",format:"hc",errorCode:"ENGINE_TIMEOUT"});
 const root="https://panel.example.test";
 const login=new Request(root+"/api/admin/login",{
  method:"POST",headers:{"Origin":root,"X-SPDecode-Admin-Action":"1","Content-Type":"application/json"}
 });
 const auth=await adminLogin(redis,login,"operator",password);
 assert.ok(auth.token);
 const make=(body,cookie="",origin=root,action="1")=>new Request(root+"/api/admin/errors/reset",{
  method:"POST",headers:{"Origin":origin,"X-SPDecode-Admin-Action":action,
   "Content-Type":"application/json",Cookie:cookie},
  body:JSON.stringify(body),
 });
 const cookie="spdecode_admin_session="+auth.token;
 assert.equal((await resetErrorsRequest(make({scope:"all"}),options)).status,401);
 assert.equal((await resetErrorsRequest(make({scope:"all"},cookie,"https://evil.invalid"),options)).status,403);
 assert.equal((await resetErrorsRequest(make({scope:"format",format:"../../secret"},cookie),options)).status,400);
 assert.equal((await resetErrorsRequest(make({scope:"format",format:"unknown"},cookie),options)).status,400);
 const ok=await resetErrorsRequest(make({scope:"format",format:"hc"},cookie),options);
 assert.equal(ok.status,200);
 assert.equal((await usageReport(redis,7)).successfulDecodes,1);
 assert.equal((await usageReport(redis,7)).failedDecodes,0);
});

