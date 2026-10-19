/**
 * C7 loopback E2E: C3 session -> authenticated C2 HTTP worker -> original
 * canonical decoder. Google and Redis are EXPLICIT TEST DOUBLES only.
 */
import assert from "node:assert/strict";
import {test,before,after} from "node:test";
import {spawn,spawnSync} from "node:child_process";
import {createHash,generateKeyPairSync} from "node:crypto";
import {decodeRequest,challengeRequest,sessionRequest,capabilitiesRequest,readinessRequest}
  from "../web/lib/c3-gateway.mjs";
import {verifySignature} from "../web/lib/c3-session.mjs";

const ROOT=process.cwd(),PYTHON=process.env.PYTHON||"python";
const WORKER_TOKEN="c7-worker-synthetic-"+("w".repeat(40));
const rsa=generateKeyPairSync("rsa",{modulusLength:2048});
const account={type:"service_account",client_email:"c7-test@example.invalid",
  private_key:rsa.privateKey.export({type:"pkcs8",format:"pem"})};
Object.assign(process.env,{
 CLOUD_API_ENABLED:"true",CLOUD_TRUST_PROXY:"true",CLOUD_REDIS_URL:"redis://redis:6379",
 CLOUD_WORKER_TOKEN:WORKER_TOKEN,CLOUD_SESSION_SIGNING_KEY:"c7-sign-"+("s".repeat(45)),
 CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
 CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify(account),
 WORKER_INTERNAL_URL:"http://decoder-worker:8787",
 CLOUD_FORCE_MAINTENANCE:"false",CLOUD_ADMIN_ENABLED:"false",
 CLOUD_EHI_IMPORT_ENABLED:"false",CLOUD_NUR_FETCH_ENABLED:"false",
});
let worker,port,vectors,workerCalls=0;
class RedisFake{
 constructor(){this.values=new Map();this.counts=new Map();this.slots=new Map();}
 async get(k){return this.values.get(k)??null;}
 async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
 async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
 async incr(k){const x=(this.counts.get(k)||0)+1;this.counts.set(k,x);return x;}
 async expire(){return 1;}
 async ping(){return "PONG";}
 async eval(_,{keys,arguments:args}){
  const k=keys[0],active=this.slots.get(k)||new Map();
  for(const [id,at] of active){if(at<=Number(args[2]))active.delete(id);}
  if(active.size>=Number(args[1]))return 0;
  active.set(args[0],Number(args[3]));this.slots.set(k,active);return 1;
 }
 async zRem(k,id){this.slots.get(k)?.delete(id);return 1;}
 multi(){
  const client=this,cmds=[];
  const tx={incr(k){cmds.push(["incr",k]);return tx;},
    expire(k,n){cmds.push(["expire",k,n]);return tx;},
    async exec(){for(const [method,...args] of cmds)await client[method](...args);return [];}};
  return tx;
 }
}
const sha=x=>createHash("sha256").update(x).digest("hex");
const send=(path,data,token="",ip="203.0.113.45")=>new Request("https://api.spdecode.example"+path,{
 method:"POST",headers:{"Content-Type":"application/json","X-Real-IP":ip,
  ...(token?{Authorization:"Bearer "+token}:{})},body:JSON.stringify(data),
});
const fetchWorker=(url,options)=>{
 assert.ok(url.startsWith("http://decoder-worker:8787/"));
 workerCalls++;
 return fetch("http://127.0.0.1:"+port+url.slice("http://decoder-worker:8787".length),options);
};
const options=redis=>({storeProvider:async()=>redis,fetchImpl:fetchWorker});
async function bearer(redis){
 const challenge=await challengeRequest(send("/api/v1/session/challenge",{}),options(redis));
 assert.equal(challenge.status,201);
 const {nonce,challengeId}=await challenge.json();
 let observed=false;
 const response=await sessionRequest(send("/api/v1/session",{
  challengeId,integrityToken:"synthetic-google-verdict-"+("T".repeat(90)),
 }),{storeProvider:async()=>redis,verifyIntegrity:async(token,seen,cfg)=>{
  observed=true;assert.equal(seen,nonce);
  assert.equal(cfg.packageName,"com.ghostdeveloper.spdecode");
  return token.startsWith("synthetic-google-verdict-");
 }});
 assert.equal(observed,true);assert.equal(response.status,201);
 const result=await response.json();
 assert.ok(verifySignature(result.accessToken,process.env.CLOUD_SESSION_SIGNING_KEY));
 return result.accessToken;
}
before(async()=>{
 const result=spawnSync(PYTHON,["cloud/tests/c7_vectors.py"],{
  cwd:ROOT,encoding:"utf8",timeout:60000,maxBuffer:3*1024*1024,
  env:{...process.env,PYTHONPATH:"cloud/workers/python:."},
 });
 if(result.status!==0)throw Error("C7_VECTORS_FAILED: "+result.stderr.slice(-500));
 vectors=JSON.parse(result.stdout);
 assert.equal(vectors.license,"synthetic-test-input-only");
 assert.equal(vectors.cases.length,3);
 const boot="from http.server import ThreadingHTTPServer\n"+
  "from server import WorkerHandler\n"+
  "s=ThreadingHTTPServer(('127.0.0.1',0),WorkerHandler)\n"+
  "print(s.server_port,flush=True)\n"+
  "s.serve_forever()\n";
 worker=spawn(PYTHON,["-B","-u","-c",boot],{
  cwd:ROOT,env:{...process.env,PYTHONPATH:"cloud/workers/python:.",CLOUD_WORKER_TOKEN:WORKER_TOKEN},
  stdio:["ignore","pipe","pipe"],
 });
 port=await new Promise((resolve,reject)=>{
  let value="",done=false;
  const timer=setTimeout(()=>{if(!done){done=true;reject(Error("WORKER_TIMEOUT"));}},12000);
  worker.stdout.on("data",bytes=>{
   if(done)return;value+=bytes.toString("utf8");
   if(!value.includes("\n"))return;
   done=true;clearTimeout(timer);const n=Number(value.trim().split("\n")[0]);
   if(!Number.isInteger(n)||n<1000)reject(Error("BAD_PORT"));else resolve(n);
  });
  worker.once("error",err=>{if(!done){done=true;clearTimeout(timer);reject(err);}});
  worker.once("exit",code=>{if(!done){done=true;clearTimeout(timer);reject(Error("WORKER_EXIT:"+code));}});
 });
 assert.equal((await fetch("http://127.0.0.1:"+port+"/health")).status,200);
});
after(()=>{if(worker&&!worker.killed)worker.kill("SIGTERM");});
test("C7 real worker private authorization and catalog count",async()=>{
 const base="http://127.0.0.1:"+port;
 assert.equal((await fetch(base+"/internal/v1/capabilities")).status,403);
 const r=await fetch(base+"/internal/v1/capabilities",{
  headers:{"X-SP-Worker-Token":WORKER_TOKEN},
 });
 assert.equal(r.status,200);const value=await r.json();
 assert.equal(value.fileRouteCount,240);assert.equal(value.exporterCertified,false);
});
test("C7 ready and capabilities originate from actual private worker",async()=>{
 const redis=new RedisFake();
 assert.equal((await readinessRequest(options(redis))).status,200);
 const response=await capabilitiesRequest({fetchImpl:fetchWorker});
 assert.equal(response.status,200);
 const data=await response.json();
 assert.equal(data.enabledFormats.length,240);
 assert.equal(data.fileDecoderCatalog.exporterVersionsCertified,0);
});
test("C7 source to worker to API exact UTF-8 output parity for 3 independent formats",async()=>{
 const redis=new RedisFake(),token=await bearer(redis),times=[];
 for(const sample of vectors.cases){
  assert.equal(sha(Buffer.from(sample.dataBase64,"base64")),sample.inputSha256);
  const start=performance.now();
  const response=await decodeRequest(send("/api/v1/decode/file",{
    format:sample.format,dataBase64:sample.dataBase64,
  },token),"file",options(redis));
  const result=await response.json();
  assert.equal(response.status,200,sample.id+" "+JSON.stringify(result.error||{}));
  assert.equal(result.status,"success");assert.equal(result.isPartial,false);
  assert.equal(result.rawText,sample.rawText,"Full output drift: "+sample.id);
  assert.equal(sha(Buffer.from(result.rawText,"utf8")),sample.referenceSha256);
  assert.equal(result.decoder.exporterCertified,false);
  assert.ok(result.requestId);
  times.push(performance.now()-start);
 }
 const p95=times.sort((a,b)=>a-b)[Math.ceil(times.length*.95)-1];
 console.log("C7 synthetic loopback p95_ms:",Math.round(p95),"(not a hardware SLO)");
});
test("C7 invalid tokens never reach worker",async()=>{
 const redis=new RedisFake(),token=await bearer(redis),before=workerCalls;
 const data={format:"v2",dataBase64:vectors.cases[0].dataBase64};
 for(const forged of ["",token.slice(0,-5)+"ABCDE","fake.token"]){
  assert.equal((await decodeRequest(send("/api/v1/decode/file",data,forged),
     "file",options(redis))).status,401);
 }
 assert.equal(workerCalls,before);
});
test("C7 invalid paths, Base64 and foreign credentials are denied before worker",async()=>{
 const redis=new RedisFake(),token=await bearer(redis),before=workerCalls;
 const samples=[
  {format:"../v2",dataBase64:"YWJj"},
  {format:"v2",dataBase64:"YWJ j"},
  {format:"v2",dataBase64:"YWJj",credentials:{password:"secret"}},
  {format:"v2",dataBase64:""},
 ];
 for(const data of samples)
  assert.equal((await decodeRequest(send("/api/v1/decode/file",data,token),
      "file",options(redis))).status,400);
 assert.equal(workerCalls,before);
});
test("C7 real worker returns sanitized errors to API and Android",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 const r=await decodeRequest(send("/api/v1/decode/file",{
   format:"v2",dataBase64:Buffer.from("bad synthetic data").toString("base64"),
 },token),"file",options(redis));
 assert.equal(r.status,422);
 const result=await r.json();
 assert.equal(result.error.code,"DECODE_FAILED");
 const body=JSON.stringify(result);
 for(const secret of [WORKER_TOKEN,"Traceback","decoders/"])
  assert.equal(body.includes(secret),false);
});
test("C7 per-token minute throttle rejects request eleven",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 const fake={storeProvider:async()=>redis,fetchImpl:async()=>({
  status:200,text:async()=>JSON.stringify({
   status:"success",isPartial:false,rawText:"complete\n",
  }),
 })};
 const body={format:"v2",dataBase64:"YWJj"};
 for(let i=0;i<10;i++){
  const r=await decodeRequest(send("/api/v1/decode/file",body,token),"file",fake);
  assert.equal(r.status,200,"request "+i);
 }
 const denied=await decodeRequest(send("/api/v1/decode/file",body,token),"file",fake);
 assert.equal(denied.status,429);
 assert.equal((await denied.json()).error.code,"RATE_LIMITED");
});
test("C7 shared Redis concurrency lease blocks third overlapping request",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 let seen=0;const held=[];
 const fake={storeProvider:async()=>redis,fetchImpl:()=>{
  seen++;return new Promise(resolve=>held.push(()=>resolve({
   status:200,text:async()=>JSON.stringify({status:"success",isPartial:false,rawText:"ok"}),
  })));
 }};
 const body={format:"v2",dataBase64:"YWJj"};
 const a=decodeRequest(send("/api/v1/decode/file",body,token),"file",fake);
 const b=decodeRequest(send("/api/v1/decode/file",body,token),"file",fake);
 for(let i=0;i<200&&seen<2;i++)await new Promise(r=>setTimeout(r,5));
 assert.equal(seen,2);
 const third=await decodeRequest(send("/api/v1/decode/file",body,token),"file",fake);
 assert.equal(third.status,429);assert.equal(seen,2);
 held.splice(0).forEach(release=>release());
 assert.equal((await a).status,200);assert.equal((await b).status,200);
});
test("C7 actual protected HCCFG requires a password and returns complete JSON after auth",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 const vector=vectors.extras.hc;
 const payload={format:"hc",dataBase64:vector.dataBase64};
 const before=await decodeRequest(send("/api/v1/decode/file",payload,token),"file",options(redis));
 assert.equal(before.status,422);
 assert.equal((await before.json()).error.code,"PASSWORD_REQUIRED");
 const forged=await decodeRequest(send("/api/v1/decode/file",{
  ...payload,credentials:{password:"wrong-synthetic-password"},
 },token),"file",options(redis));
 assert.equal(forged.status,422);
 const response=await decodeRequest(send("/api/v1/decode/file",{
  ...payload,credentials:vector.credentials,
 },token),"file",options(redis));
 assert.equal(response.status,200);
 const decoded=await response.json();
 assert.equal(decoded.rawText,vector.rawText);
 assert.deepEqual(decoded.structuredJson,vector.structuredJson);
 assert.equal(decoded.isPartial,false);
});
test("C7 actual text protocol preserves full structured JSON and text",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 const vector=vectors.extras.text;
 const response=await decodeRequest(send("/api/v1/decode/text",{
  text:vector.input,
 },token),"text",options(redis));
 assert.equal(response.status,200);
 const decoded=await response.json();
 assert.equal(decoded.rawText,vector.rawText);
 assert.deepEqual(decoded.structuredJson,vector.structuredJson);
 assert.equal(decoded.isPartial,false);
});
test("C7 authenticated NUR server catalog is distinct from .solid and tampering fails",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 const vector=vectors.extras.catalog;
 const response=await decodeRequest(send("/api/v1/decode/import/catalog",{
  dataBase64:vector.dataBase64,
 },token),"catalog",options(redis));
 assert.equal(response.status,200);
 const decoded=await response.json();
 assert.equal(decoded.rawText,vector.rawText);
 assert.deepEqual(decoded.structuredJson,vector.structuredJson);
 assert.equal(decoded.kind,"nur_catalog");
 assert.equal(decoded.isPartial,false);
 const damaged=Buffer.from(vector.dataBase64,"base64");
 damaged[20]^=1;
 const corrupted=await decodeRequest(send("/api/v1/decode/import/catalog",{
  dataBase64:damaged.toString("base64"),
 },token),"catalog",options(redis));
 assert.equal(corrupted.status,422);
});
test("C7 maintenance closes API before dispatch and disables readiness",async()=>{
 const redis=new RedisFake(),token=await bearer(redis);
 await redis.set("spc6:maintenance","1");
 const initial=workerCalls;
 const r=await decodeRequest(send("/api/v1/decode/file",{
  format:"v2",dataBase64:vectors.cases[0].dataBase64,
 },token),"file",options(redis));
 assert.equal(r.status,503);
 assert.equal((await readinessRequest(options(redis))).status,503);
 assert.equal(workerCalls,initial);
});
