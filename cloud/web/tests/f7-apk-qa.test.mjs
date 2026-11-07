import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {apkQaRequest} from "../lib/f7-apk-qa-gateway.mjs";
import {bindVerifiedRequest} from "../lib/v2-bound-request.mjs";
import {routes,bodyLimit} from "../lib/v2-routes.mjs";
import {protectedActions} from "../lib/action-integrity.mjs";
import {unpackHpkeBody} from "../lib/v2-hpke.mjs";

const cfg={CLOUD_APK_QA_ENABLED:"true",CLOUD_APK_QA_INTERNAL_TOKEN:"z".repeat(48)};
function request(body,op,authorized=true){
  const req=new Request("https://api.spdecode.test/api/v1/apk-qa/test",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify(body)});
  if(authorized)bindVerifiedRequest(req,{
    hpke:true,key:"device-p256-public-key-verifiable-qa-test",scope:"decode",versionCode:42});
  return req;
}
function sender(handler){
  let count=0,captured;
  return {
    get count(){return count},get captured(){return captured},
    async send(url,options){
      count++;captured={url,options,body:JSON.parse(options.body)};
      return handler?.(url,options)||Response.json({status:"UPLOADING",jobId:"a".repeat(32)},{
        status:200,headers:{"content-type":"application/json"}});
    }
  };
}
test("non-commercial QA operations are separate from all older V2 operations",()=>{
  for(let n=21;n<=24;n++)assert.match(routes[n],/^apk-qa\//);
  assert.equal(routes[5],"decode/file");
  assert.equal(routes[18],"feedback");
  assert.equal(bodyLimit(22),3*1024*1024);
  assert.equal(bodyLimit(21),4096);
  assert.equal(protectedActions.has(21),true);
  assert.equal(protectedActions.has(23),true);
  assert.equal(protectedActions.has(22),false);
});
test("direct fake headers cannot create V2-bound authentication",async()=>{
  const a=sender();
  const result=await apkQaRequest(request({consent:true,qaFirstPass:true},21,false),21,
    {env:cfg,send:a.send});
  assert.equal(result.status,401);
  assert.equal(a.count,0);
});
test("feature toggle fail-closed even with a verified caller",async()=>{
  const a=sender();
  const result=await apkQaRequest(request({consent:true,qaFirstPass:true},21),21,{
    env:{...cfg,CLOUD_APK_QA_ENABLED:"false"},send:a.send});
  assert.equal(result.status,503);
  assert.equal(a.count,0);
});
test("start requires explicit consent and static-only acknowledgment",async()=>{
  const a=sender();
  const result=await apkQaRequest(request({consent:false,qaFirstPass:true},21),21,{
    env:cfg,send:a.send});
  assert.equal(result.status,403);
  assert.equal(a.count,0);
});
test("actual device binding is injected after verification, never trusted from client",async()=>{
  const a=sender();
  const result=await apkQaRequest(request({
    filename:"sample.apk",consent:true,qaFirstPass:true,totalBytes:1000,sha256:"a".repeat(64),
    deviceKeyHash:"f".repeat(64)},21),21,{env:cfg,send:a.send});
  assert.equal(result.status,200);
  const captured=a.captured;
  assert.equal(captured.url,"http://apk-qa:8792/internal/qa/start");
  assert.equal(captured.options.headers["x-sp-apk-internal"],cfg.CLOUD_APK_QA_INTERNAL_TOKEN);
  assert.equal(captured.body.deviceKeyHash,
    createHash("sha256").update("device-p256-public-key-verifiable-qa-test").digest("hex"));
  assert.notEqual(captured.body.deviceKeyHash,"f".repeat(64));
});
test("HPKE binary 2 MiB chunk is only supported for op22",()=>{
  const body={jobId:"a".repeat(32),uploadToken:"x".repeat(43),index:0,chunkSha256:"b".repeat(64)};
  const header=Buffer.from(JSON.stringify(body));
  const tail=Buffer.from([1,2,3,4,5]);
  const raw=Buffer.alloc(4+header.length+tail.length);
  raw.writeUInt32BE(header.length,0);header.copy(raw,4);tail.copy(raw,4+header.length);
  const output=JSON.parse(unpackHpkeBody(raw,22));
  assert.equal(output.dataBase64,tail.toString("base64"));
  assert.throws(()=>unpackHpkeBody(raw,21),/HPKE_INVALID/);
  assert.throws(()=>unpackHpkeBody(raw,24),/HPKE_INVALID/);
});
test("no overlarge untrusted JSON or arbitrary op is dispatched",async()=>{
  const a=sender();
  const large=await apkQaRequest(request({dataBase64:"x".repeat(3*1024*1024+5)},22),22,
    {env:cfg,send:a.send});
  assert.equal(large.status,413);
  const unexpected=await apkQaRequest(request({},25),25,{env:cfg,send:a.send});
  assert.equal(unexpected.status,400);
  assert.equal(a.count,0);
});
test("service failures return status codes and never leak internal response bodies",async()=>{
  const a=sender(()=>Response.json({error:"CHUNK_HASH_MISMATCH"},{
    status:422,headers:{"content-type":"application/json"}}));
  const result=await apkQaRequest(request({index:0},22),22,{env:cfg,send:a.send});
  assert.equal(result.status,422);
  assert.deepEqual(await result.json(),{error:{code:"CHUNK_HASH_MISMATCH"}});
});
test("non-JSON private errors are replaced by a stable no-secret failure",async()=>{
  const a=sender(()=>new Response("secret internal stacktrace",{status:500}));
  const result=await apkQaRequest(request({index:0},22),22,{env:cfg,send:a.send});
  assert.equal(result.status,503);
  assert.deepEqual(await result.json(),{error:{code:"APK_QA_UNAVAILABLE"}});
});
