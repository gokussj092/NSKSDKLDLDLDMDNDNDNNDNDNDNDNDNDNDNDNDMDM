import assert from "node:assert/strict";
import {test} from "node:test";
import {randomBytes,scryptSync} from "node:crypto";
import {adminLogin} from "../lib/c6-admin-auth.mjs";
import {reportRequest} from "../lib/c6-admin-api.mjs";
import {recordWorkerResult,usageReport,safeFormat,safeErrorCode} from "../lib/c6-ops-store.mjs";

class RedisFake {
  constructor(){this.kv=new Map();this.hash=new Map();this.counter=new Map();}
  async get(key){return this.kv.get(key)??null;}
  async set(key,value,opts={}){if(opts.NX&&this.kv.has(key))return null;this.kv.set(key,value);return "OK";}
  async incr(key){const n=(this.counter.get(key)||0)+1;this.counter.set(key,n);return n;}
  async expire(){return 1;}
  async hIncrBy(key,field,amount){
    const map=this.hash.get(key)||{};
    map[field]=(map[field]||0)+amount;this.hash.set(key,map);
    return map[field];
  }
  async hGetAll(key){return this.hash.get(key)||{};}
  async mGet(keys){return keys.map(k=>String(this.counter.get(k)||0));}
  multi(){
    const commands=[];const obj={
      incr:(...args)=>{commands.push(["incr",...args]);return obj;},
      hIncrBy:(...args)=>{commands.push(["hIncrBy",...args]);return obj;},
      expire:(...args)=>{commands.push(["expire",...args]);return obj;},
      exec:async()=>{for(const [method,...args] of commands)await this[method](...args);return [];}
    };return obj;
  }
}
test("seven-day analytics tracks sanitized extensions, bytes and error buckets",async()=>{
  const redis=new RedisFake();
  await recordWorkerResult(redis,"success",{kind:"file",format:"hc",bytes:234});
  await recordWorkerResult(redis,"failed",{kind:"file",format:"hc",bytes:100,errorCode:"AUTH_FAILED"});
  await recordWorkerResult(redis,"success",{kind:"file",format:"npvs",bytes:450});
  await recordWorkerResult(redis,"failed",{kind:"file",format:"random_unrecognized",bytes:15,errorCode:"UNSUPPORTED_FORMAT"});
  await recordWorkerResult(redis,"success",{kind:"text",bytes:10});
  await recordWorkerResult(redis,"failed",{kind:"catalog",bytes:80,errorCode:"ENGINE_TIMEOUT"});
  const report=await usageReport(redis,7);
  assert.equal(report.totalDecodes,6);
  assert.equal(report.successfulDecodes,3);
  assert.equal(report.failedDecodes,2);
  assert.equal(report.warnings,1);
  assert.equal(report.inputBytes,889);
  assert.deepEqual(report.extensions.find(x=>x.extension==="hc"),{
    extension:"hc",successfulDecodes:1,failedDecodes:1,attempts:2});
  assert.equal(report.extensions.find(x=>x.extension==="other").warnings,1);
  assert.equal(report.extensions.find(x=>x.extension==="other").failedDecodes,0);
  assert.equal(report.errors.find(x=>x.code==="AUTH_FAILED").count,1);
  assert.ok(report.incidents.some(x=>x.extension==="hc"&&x.code==="AUTH_FAILED"));
  assert.equal(report.daily.reduce((n,d)=>n+d.successfulDecodes,0),3);
  const keys=[...redis.hash.keys()].join(" ");
  assert.doesNotMatch(keys,/password|ip|filename|payload|dataBase64/);
  assert.equal((await usageReport(redis,1)).totalDecodes,6);
});
test("untrusted extension and error strings cannot create arbitrary Redis labels",()=>{
  assert.equal(safeFormat("file","../../secrets","DECODE_FAILED"),"other");
  assert.equal(safeFormat("file","_bad","DECODE_FAILED"),"other");
  assert.equal(safeFormat("file","unknown_valid","UNSUPPORTED_FORMAT"),"other");
  assert.equal(safeFormat("ehi","untrusted"),"ehi");
  assert.equal(safeFormat("catalog","untrusted"),"nur-catalog");
  assert.equal(safeErrorCode("password=secret-file-content"),"OTHER_ERROR");
});
test("report API requires signed admin session, never supports public or malformed access",async()=>{
  const salt=randomBytes(16),password="long-password-used-for-ci-tests-123";
  Object.assign(process.env,{
    CLOUD_ADMIN_ENABLED:"true",CLOUD_TRUST_PROXY:"true",
    CLOUD_ADMIN_USERNAME:"testoperator",
    CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+
      scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex"),
    CLOUD_ADMIN_SESSION_KEY:"a".repeat(64),
    CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test",
    CLOUD_REDIS_URL:"redis://redis:6379"
  });
  const redis=new RedisFake(),args={storeProvider:async()=>redis};
  const url="https://panel.example.test/api/admin/reports";
  const guest=await reportRequest(new Request(url),args);
  assert.equal(guest.status,401);
  const invalid=await reportRequest(new Request(url+"?days=365"),args);
  assert.equal(invalid.status,401);
  const request=new Request("https://panel.example.test/api/admin/login",{
    method:"POST",headers:{"origin":"https://panel.example.test",
      "x-spdecode-admin-action":"1","content-type":"application/json"}
  });
  const logged=await adminLogin(redis,request,"testoperator",password);
  assert.ok(logged.token);
  const cookie="spdecode_admin_session="+logged.token;
  const call=async u=>reportRequest(new Request(u,{headers:{cookie}}),args);
  assert.equal((await call(url+"?days=365")).status,400);
  assert.equal((await call(url+"?days=7&foo=bar")).status,400);
  const reportResponse=await call(url+"?days=7");
  assert.equal(reportResponse.status,200);
  assert.match(reportResponse.headers.get("cache-control"),/no-store/);
  const body=await reportResponse.json();
  assert.equal(body.report.privacy,"anonymous_aggregate_counters");
  assert.equal(JSON.stringify(body).includes(password),false);
});

test("file and Server VPN success/failure diagnostics are counted separately without storing payloads",async()=>{
  const redis=new RedisFake();
  await recordWorkerResult(redis,"success",{kind:"file",format:"npvs",bytes:200});
  await recordWorkerResult(redis,"failed",{kind:"file",format:"hc",bytes:100,errorCode:"AUTH_FAILED"});
  await recordWorkerResult(redis,"failed",{kind:"server-vpn",format:"tunneltweak",bytes:400,errorCode:"ENGINE_TIMEOUT"});
  await recordWorkerResult(redis,"success",{kind:"server-vpn",format:"nur-tunnel",bytes:300});
  await recordWorkerResult(redis,"failed",{kind:"ehi",bytes:200,errorCode:"REMOTE_DECODER_FAILED"});
  const result=await usageReport(redis,7);
  const lookup=id=>result.serviceBreakdown.find(s=>s.service===id);
  assert.deepEqual(lookup("files"),{service:"files",successfulDecodes:1,failedDecodes:1,attempts:2});
  assert.deepEqual(lookup("httpInjector"),{service:"httpInjector",successfulDecodes:0,failedDecodes:1,attempts:1});
  assert.deepEqual(lookup("serverVpn"),{service:"serverVpn",successfulDecodes:1,failedDecodes:1,attempts:2});
  assert.ok(result.extensions.some(e=>e.extension==="vpn-tunneltweak"&&e.failedDecodes===1));
  assert.ok(result.serviceErrors.some(e=>e.service==="serverVpn"&&e.code==="ENGINE_TIMEOUT"));
  assert.equal(result.hourlyLast48.length,48);
  assert.equal(result.hourlyLast48.reduce((n,h)=>n+h.successfulDecodes+h.failedDecodes,0),5);
  assert.ok(![...redis.hash.keys()].join(" ").includes("password"));
  assert.equal(safeFormat("server-vpn","../private"),"vpn-other");
  assert.equal(safeFormat("server-vpn","nur-tunnel"),"vpn-nur-tunnel");
});
