/** Real Node transport, or explicitly mocked HTTP using real saved responses. */
import fs from "node:fs";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";
import {CATNET_PREFLIGHT,CATNET_SOURCE} from "../../../../cloud/web/lib/catnet-protocol.mjs";
process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,preflightFile,serverFile,workerFile]=process.argv.slice(2);
if(mode==="--real"){
 try{const data=await downloadVpnCatalog("catnet-vpn");console.log(JSON.stringify({transport:"REAL_HTTP",bytes:data.length,status:"PASS"}));}
 catch(e){console.log(JSON.stringify({transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:e.code||e.message}));process.exitCode=3;}
}else if(mode==="--replay"){
 const meta=fs.readFileSync(preflightFile),raw=fs.readFileSync(serverFile),worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
 const lookup=dns.lookup,request=https.request;let calls=0;
 try{
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,options,callback)=>{
   assert.equal(url.href,calls===0?CATNET_PREFLIGHT:CATNET_SOURCE);assert.equal(options.method,"GET");
   assert.equal(options.headers["User-Agent"],"okhttp/4.12.0");const data=calls++===0?meta:raw;
   const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
    const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};callback(res);res.emit("data",data);res.emit("end");
   });return req;
  };
  const data=await downloadVpnCatalog("catnet-vpn");assert.deepEqual(data,raw);
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  const result=await fetchWorker("server-vpn",{providerId:"catnet-vpn",dataBase64:data.toString("base64")},
   {workerToken:"synthetic-internal-replay"},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await result.json()).structuredJson,JSON.parse(raw));
  console.log(JSON.stringify({transport:"SIMULATED_HTTP_REAL_BYTES",calls,servers:worker.structuredJson.servers.length,whole_worker_equal:true}));
 }finally{dns.lookup=lookup;https.request=request;}
}else throw Error("Choose --real or --replay");
