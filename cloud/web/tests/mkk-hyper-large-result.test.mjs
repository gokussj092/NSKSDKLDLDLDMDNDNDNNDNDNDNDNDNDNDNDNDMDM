import test from "node:test";
import assert from "node:assert/strict";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {MKK_BUNDLE_LIMIT,MKK_NAMES,packMkkSources} from "../lib/mkk-source-bundle.mjs";

const config={workerToken:"w".repeat(48)};
function workerEnvironment(){
 const previous=process.env.WORKER_INTERNAL_URL;
 process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 return ()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;
   else process.env.WORKER_INTERNAL_URL=previous;};
}
function report(big=""){
 const sources=MKK_NAMES.map((name,i)=>({name,status:"ok",records:1,
   data:{servers:[{id:i,description:i===0?big:"small"}]}}));
 return {provider:"mkk-hyper",complete:true,sourceCount:4,
   successfulSources:4,sources};
}
function reply(doc,raw=JSON.stringify(doc)){
 return Response.json({apiVersion:"v1",status:"success",kind:"vpn_catalog",
   providerId:"mkk-hyper",rawText:raw,structuredJson:doc,isPartial:false,
   warnings:[],exporterCertified:false});
}
const run=async response=>fetchWorker("server-vpn",
 {providerId:"mkk-hyper",dataBase64:"ZGF0YQ=="},config,
 {fetchImpl:async()=>response});

test("MKK complete valid JSON above former 4 MiB is accepted without truncation",async()=>{
 const restore=workerEnvironment();
 try{
  const big="x".repeat(4*1024*1024+512);
  const doc=report(big);
  const response=await run(reply(doc));
  assert.equal(response.status,200);
  const parsed=await response.json();
  assert.equal(parsed.isPartial,false);
  assert.equal(parsed.structuredJson.sources[0].data.servers[0].description,big);
  assert.deepEqual(JSON.parse(parsed.rawText),parsed.structuredJson);
 }finally{restore();}
});

test("MKK rejects HTML, truncated JSON and mismatched structured data",async()=>{
 const restore=workerEnvironment();
 try{
  const doc=report("good");
  for(const raw of ["<html>not json</html>",JSON.stringify(doc).slice(0,-1),
    JSON.stringify({...doc,successfulSources:3})]){
    await assert.rejects(()=>run(reply(doc,raw)),/INVALID_WORKER_RESULT/);
  }
 }finally{restore();}
});

test("Non-MKK output still rejects oversized responses",async()=>{
 const restore=workerEnvironment();
 try{
  const large=Response.json({status:"success",rawText:"x".repeat(7*1024*1024),
    structuredJson:{},isPartial:false,warnings:[]});
  await assert.rejects(()=>fetchWorker("file",{format:"tls"},config,
    {fetchImpl:async()=>large}),/OUTPUT_OVER_LIMIT/);
 }finally{restore();}
});

test("MKK bundle retains all four valid sources above the former 12 MiB aggregate",()=>{
 const source=Buffer.alloc(2_700_000,0x31).toString("base64");
 const items=MKK_NAMES.map(name=>({name,status:"ok",dataBase64:source}));
 const packed=packMkkSources(items);
 assert(packed.payload.length>12*1024*1024);
 assert(packed.payload.length<MKK_BUNDLE_LIMIT);
 assert.equal(packed.sources.filter(x=>x.status==="ok").length,4);
 assert.deepEqual(JSON.parse(packed.payload).sources.map(x=>x.name),MKK_NAMES);
});
