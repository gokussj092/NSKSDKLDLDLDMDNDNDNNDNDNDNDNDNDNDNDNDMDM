/** Real Node egress, or explicitly simulated HTTP with the saved real bytes. */
import fs from "node:fs";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";
process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,rawFile,workerFile]=process.argv.slice(2),id="xxpicore-tunnel";
if(mode==="--real"){
 try{const data=await downloadVpnCatalog(id);console.log(JSON.stringify({transport:"REAL_HTTP",bytes:data.length,status:"PASS"}));}
 catch(e){console.log(JSON.stringify({transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:e.code||e.message}));process.exitCode=3;}
}else if(mode==="--replay"){
 const raw=fs.readFileSync(rawFile),worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
 const lookup=dns.lookup,request=https.request;let calls=0;
 try{
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,options,callback)=>{
   assert.equal(url.href,"https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xxpicoretunnel888.hs");
   assert.equal(options.method,"GET");assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0 (Linux; U; Android 14)");calls++;
   const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
    const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};callback(res);res.emit("data",raw);res.emit("end");
   });return req;
  };
  const data=await downloadVpnCatalog(id);assert.deepEqual(data,raw);
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  const result=await fetchWorker("server-vpn",{providerId:id,dataBase64:data.toString("base64")},
   {workerToken:"synthetic-internal-replay"},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await result.json()).structuredJson,worker.structuredJson);
  console.log(JSON.stringify({transport:"SIMULATED_HTTP_REAL_BYTES",calls,wholeWorkerEqual:true,version:worker.structuredJson.Version,
    servers:worker.structuredJson.Servers.length,networks:worker.structuredJson.Networks.length}));
 }finally{dns.lookup=lookup;https.request=request;}
}else throw Error("Choose --real or --replay");
