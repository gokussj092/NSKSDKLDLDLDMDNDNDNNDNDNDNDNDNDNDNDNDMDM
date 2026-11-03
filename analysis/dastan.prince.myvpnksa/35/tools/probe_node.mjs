/** Test real Node transport once, or replay real bytes with explicitly simulated HTTP. */
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";
process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,responseFile,workerFile]=process.argv.slice(2);
if(mode==="--real"){
 try{
  const data=await downloadVpnCatalog("fnf-tunnel-bd");fs.writeFileSync(responseFile,data,{mode:0o600});
  console.log(JSON.stringify({transport:"REAL_HTTP",bytes:data.length,status:"PASS"}));
 }catch(e){console.log(JSON.stringify({transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:e.code||e.message}));process.exitCode=3;}
}else if(mode==="--replay"){
 const data=fs.readFileSync(responseFile),worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
 const lookup=dns.lookup,request=https.request;let calls=0;
 try{
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,options,callback)=>{
   assert.equal(url.href,"https://raw.githubusercontent.com/pipoyrichards/FNFTUNNELBD/refs/heads/main/FEB52025");
   assert.equal(options.headers["User-Agent"],"FNF TUNNEL BD/PrinceBuild35");assert.equal(options.method,"GET");
   const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
    calls++;const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};
    callback(res);res.emit("data",data);res.emit("end");
   });return req;
  };
  const actual=await downloadVpnCatalog("fnf-tunnel-bd");assert.deepEqual(actual,data);
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  const result=await fetchWorker("server-vpn",{providerId:"fnf-tunnel-bd",dataBase64:actual.toString("base64")},
   {workerToken:"synthetic-internal-replay"},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await result.json()).structuredJson,worker.structuredJson);
  console.log(JSON.stringify({transport:"SIMULATED_HTTP_REAL_BYTES",calls,whole_worker_contract_equal:true,
    version:worker.structuredJson.Version,servers:worker.structuredJson.Free_servers.length}));
 }finally{dns.lookup=lookup;https.request=request;}
}else throw Error("Choose --real or --replay");
