/** Real Node transport once, or explicitly simulated HTTP with real bytes/worker. */
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHash} from "node:crypto";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";
import {HTTP_CONEXION_SOURCE} from "../../../../cloud/web/lib/http-conexion-protocol.mjs";
process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,responseFile,workerFile]=process.argv.slice(2);
if(mode==="--real"){
 try{const data=await downloadVpnCatalog("http-conexion");fs.writeFileSync(responseFile,data,{mode:0o600});
  console.log(JSON.stringify({transport:"REAL_HTTP",bytes:data.length,sha256:createHash('sha256').update(data).digest('hex'),status:"PASS"}));
 }catch(e){console.log(JSON.stringify({transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:e.code||e.message}));process.exitCode=3;}
}else if(mode==="--replay"){
 const data=fs.readFileSync(responseFile),worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
 const lookup=dns.lookup,request=https.request;let calls=0;
 try{
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,o,callback)=>{
   assert.equal(url.origin+url.pathname,HTTP_CONEXION_SOURCE);assert.match(url.search,/^\?nocache=[0-9]+$/);
   assert.equal(o.method,"GET");assert.equal(o.headers["User-Agent"],"HTTP-Conexion-VPN/3.0");
   assert.equal(o.headers["Cache-Control"],"no-cache, no-store, must-revalidate");assert.equal(o.rejectUnauthorized,true);
   const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
    calls++;const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};
    callback(res);res.emit("data",data);res.emit("end");
   });return req;
  };
  const actual=await downloadVpnCatalog("http-conexion");assert.deepEqual(actual,data);
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  const result=await fetchWorker("server-vpn",{providerId:"http-conexion",dataBase64:actual.toString("base64")},
   {workerToken:"synthetic-internal-replay"},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await result.json()).structuredJson,worker.structuredJson);
  console.log(JSON.stringify({transport:"SIMULATED_HTTP_REAL_BYTES",calls,ciphertextBytes:data.length,
   whole_worker_contract_equal:true,version:worker.structuredJson.Version,servers:worker.structuredJson.Servers.length}));
 }finally{dns.lookup=lookup;https.request=request;}
}else throw Error("Choose --real or --replay");
