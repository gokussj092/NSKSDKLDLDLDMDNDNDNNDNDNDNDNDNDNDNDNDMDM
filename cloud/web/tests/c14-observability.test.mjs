import {test} from "node:test";
import assert from "node:assert/strict";
import {randomBytes,scryptSync} from "node:crypto";
import {latencyBucket,latencySummary,recordOpsTelemetry,readOpsReport,recordAdminAudit,hostHealth} from "../lib/c14-ops-observability.mjs";
import {adminLogin} from "../lib/c6-admin-auth.mjs";
import {observabilityRequest} from "../lib/c6-admin-api.mjs";
import {rtEnvelopeVersion} from "../lib/c3-gateway.mjs";

class FakeRedis{
 constructor(){this.strings=new Map();this.hashes=new Map();this.lists=new Map();this.counters=new Map();}
 async get(k){return this.strings.get(k)??null;}
 async set(k,v,{NX}={}){if(NX&&this.strings.has(k))return null;this.strings.set(k,v);return "OK";}
 async eval(script,opts){if(script.includes("spdecode:throttle:v1"))return this.incr(opts.keys[0]);throw Error("Unsupported Lua");}
  async incr(k){const n=(this.counters.get(k)||0)+1;this.counters.set(k,n);return n;}
 async expire(){return 1;}
 async mGet(keys){return keys.map(x=>String(this.counters.get(x)||0));}
 async hGetAll(k){return this.hashes.get(k)||{};}
 async hSet(k,field,value){const a=this.hashes.get(k)||{};a[field]=value;this.hashes.set(k,a);return 1;}
 async hIncrBy(k,field,n){const a=this.hashes.get(k)||{};a[field]=(a[field]||0)+n;this.hashes.set(k,a);return a[field];}
 async lPush(k,v){this.lists.set(k,[v,...(this.lists.get(k)||[])]);return 1;}
 async lTrim(k,a,b){this.lists.set(k,(this.lists.get(k)||[]).slice(a,b+1));return 1;}
 async lRange(k,a,b){return (this.lists.get(k)||[]).slice(a,b+1);}
 async ping(){return "PONG";}
 multi(){
  const commands=[],tx={};
  for(const method of ["hIncrBy","hSet","expire","incr","lPush","lTrim"]){
   tx[method]=(...args)=>{commands.push([method,...args]);return tx;};
  }
  tx.exec=async()=>{for(const [method,...args] of commands)await this[method](...args);return [];};
  return tx;
 }
}
test("latency mean and histogram P95 are bounded, never sample-level data",()=>{
 assert.equal(latencyBucket(3),0);assert.equal(latencyBucket(200),1);
 assert.equal(latencyBucket(-1),null);assert.equal(latencyBucket(900000),11);
 const stats=latencySummary({count:10,sum:2000,b0:1,b1:4,b2:5});
 assert.equal(stats.meanMs,200);assert.equal(stats.p95UpperBoundMs,500);
});
test("per-provider classification, alert cooldown and version counts without storing secrets",async()=>{
 const redis=new FakeRedis();
 for(let i=0;i<10;i++){
  await recordOpsTelemetry(redis,{format:"vpn-mkk-hyper",service:"serverVpn",
   outcome:i%2?"failed":"success",errorCode:"REMOTE_PROVIDER_UNAVAILABLE",
   latencyMs:250+i*30,appVersion:"1.1.6",formatVersion:"not-provided",
   password:"secret",dataBase64:"privatefile"});
 }
 const info=await readOpsReport(redis,7);
 assert.ok(info.performance.some(x=>x.label==="vpn-mkk-hyper"&&x.count===10));
 assert.equal(info.alerts.filter(a=>a.type==="failure_ratio").length,1);
 assert.equal(info.versions.find(x=>x.version==="1.1.6").count,10);
 const raw=JSON.stringify([...redis.hashes,...redis.lists]);
 for(const secret of ["privatefile","password","dataBase64"])assert.ok(!raw.includes(secret));
 for(let i=0;i<3;i++)
  await recordOpsTelemetry(redis,{format:"vpn-nur-tunnel",service:"serverVpn",
   outcome:"failed",errorCode:"ENGINE_TIMEOUT",latencyMs:120_000});
 const report=await readOpsReport(redis,7);
 assert.ok(report.alerts.some(x=>x.type==="unresponsive"&&x.format==="vpn-nur-tunnel"));
});
test("administrative action log has only allowlisted fields",async()=>{
 const redis=new FakeRedis();
 await recordAdminAudit(redis,{scope:"format",format:"rt",at:"2026-10-20T18:00:00.000Z",
  formatsReset:1,actor:"secret@example.com",ip:"192.0.2.1"});
 const report=await readOpsReport(redis,7);
 assert.deepEqual(Object.keys(report.actions[0]).sort(),["action","at","format","formatsReset","scope"]);
 assert.ok(!JSON.stringify([...redis.lists]).includes("secret@example.com"));
});
test("only known REESE version headers are reported",()=>{
 for(let ver of ["RSE1","RSE2","RSE3","RSE4"])
  assert.equal(rtEnvelopeVersion(Buffer.from(ver+"extra").toString("base64")),ver);
 assert.equal(rtEnvelopeVersion(Buffer.concat([Buffer.from([0xa7,0x19,0xd2,0x4c]),Buffer.alloc(5)]).toString("base64")),"RSE5");
 assert.equal(rtEnvelopeVersion(Buffer.from("unknown!").toString("base64")),null);
});
test("private observability endpoint authenticates and validates bounded date range",async()=>{
 const redis=new FakeRedis(),origin="https://panel.example.test";
 const salt=randomBytes(16),password="long administrative test password";
 Object.assign(process.env,{CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",
  CLOUD_ADMIN_USERNAME:"observer",
  CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+
  scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex"),
  CLOUD_ADMIN_SESSION_KEY:"c".repeat(64),
  CLOUD_ADMIN_PUBLIC_ORIGIN:origin,CLOUD_REDIS_URL:"redis://redis:6379",
  WORKER_INTERNAL_URL:"http://decoder-worker:8787"});
 const args={storeProvider:async()=>redis,fetchImpl:async()=>({ok:true})};
 const req=(suffix="",cookie="")=>new Request(origin+"/api/admin/observability"+suffix,{
  headers:{Cookie:cookie}});
 assert.equal((await observabilityRequest(req(),args)).status,401);
 const login=await adminLogin(redis,new Request(origin+"/api/admin/login",{
  method:"POST",headers:{"Origin":origin,"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"}
 }),"observer",password);
 assert.ok(login.token);
 const cookie="spdecode_admin_session="+login.token;
 assert.equal((await observabilityRequest(req("?days=30",cookie),args)).status,400);
 const response=await observabilityRequest(req("?days=1",cookie),args);
 assert.equal(response.status,200);
 const json=await response.json();
 assert.equal(json.observability.retentionDays,8);
 assert.equal(json.health.vpsHostMetricsAvailable,false);
 assert.equal(json.health.workerReady,true);
 assert.match(response.headers.get("cache-control"),/no-store/);
});

