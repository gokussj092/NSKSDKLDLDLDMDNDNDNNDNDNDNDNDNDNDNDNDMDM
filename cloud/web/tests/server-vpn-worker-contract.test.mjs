import test from "node:test";
import assert from "node:assert/strict";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {classifyWorkerOutcome,safeErrorCode} from "../lib/c6-ops-store.mjs";

const cfg={workerToken:"w".repeat(48)};
const version=()=>{
 const prev=process.env.WORKER_INTERNAL_URL;
 process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 return ()=>{if(prev===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=prev;};
};
const mkkSources=[
 {name:"servers",status:"ok",records:2,data:{servers:[{id:1},{id:2}]}},
 {name:"static",status:"error",error:"REMOTE_PROVIDER_UNAVAILABLE"},
 {name:"subscriptions",status:"error",error:"DECODE_FAILED"},
 {name:"legacy-subscriptions",status:"error",error:"REMOTE_PROVIDER_UNAVAILABLE"},
];
const result=(partial=true)=>{
 const sources=partial?mkkSources:mkkSources.map(x=>x.status==="ok"?x:
   {name:x.name,status:"ok",records:1,data:{servers:[{id:x.name}]}});
 const report={provider:"mkk-hyper",complete:!partial,sourceCount:4,
   successfulSources:partial?1:4,sources};
 return {
 apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"mkk-hyper",
 structuredJson:report,
 rawText:JSON.stringify(report),
 isPartial:partial,
 warnings:partial?["PARTIAL_SOURCE_FAILURE"]:[],
 exporterCertified:false
 };
};
const worker=(body)=>async(url,options)=>{
 assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
 assert.equal(options.method,"POST");
 assert.equal(options.headers["X-SP-Worker-Token"],cfg.workerToken);
 return Response.json(body);
};

test("MKK source failures preserve a successful partial HTTP response instead of SERVICE_UNAVAILABLE",async()=>{
 const restore=version();
 try{
  const response=await fetchWorker("server-vpn",{providerId:"mkk-hyper",dataBase64:"Zm9v"},cfg,{fetchImpl:worker(result())});
  assert.equal(response.status,200);
  const data=await response.json();
  assert.equal(data.status,"success");
  assert.equal(data.isPartial,true);
  assert.deepEqual(data.warnings,["PARTIAL_SOURCE_FAILURE"]);
  assert.equal(data.structuredJson.sources.length,4);
  assert.equal(data.structuredJson.sources[0].records,2);
  assert.equal(data.structuredJson.complete,false);
 }finally{restore();}
});

test("MKK partial responses require explicit source failures and may not hide unsupported partials",async()=>{
 const restore=version();
 try{
  const invalid=result();
  invalid.structuredJson.sources=mkkSources.filter(x=>x.status==="ok");
  await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"mkk-hyper"},cfg,{fetchImpl:worker(invalid)}),/INVALID_WORKER_RESULT/);
  await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"ksh-vpn"},cfg,{fetchImpl:worker(result())}),/INVALID_WORKER_RESULT/);
 }finally{restore();}
});

test("non-MKK and complete worker results remain strictly non-partial",async()=>{
 const restore=version();
 try{
  const ok=result(false);
  const response=await fetchWorker("server-vpn",{providerId:"mkk-hyper"},cfg,{fetchImpl:worker(ok)});
  assert.equal(response.status,200);
  const bad={...ok,isPartial:true};
  await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"mkk-hyper"},cfg,{fetchImpl:worker(bad)}),/INVALID_WORKER_RESULT/);
 }finally{restore();}
});

test("MKK partial catalog is an explicit warning, not a full success or an unknown error",()=>{
 assert.equal(safeErrorCode("PARTIAL_SOURCE_FAILURE"),"PARTIAL_SOURCE_FAILURE");
 assert.equal(classifyWorkerOutcome("warning",{kind:"server-vpn",format:"mkk-hyper",
  errorCode:"PARTIAL_SOURCE_FAILURE"}),"warning");
});
