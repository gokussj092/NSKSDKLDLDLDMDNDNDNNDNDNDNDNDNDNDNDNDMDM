/** Real Node transport or explicit offline HTTP replay with the real config pair. */
import assert from "node:assert/strict";import fs from "node:fs";import path from "node:path";
import dns from "node:dns/promises";import https from "node:https";import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {httpConexionResolver,packHttpConexionCatalog,approvedHttpConexionSource} from "../../../../cloud/web/lib/http-conexion-firebase.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";
process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,input,workerFile,configFile]=process.argv.slice(2);
let report;
if(mode==="--real"){
 try{const bundle=await downloadVpnCatalog("http-conexion");fs.writeFileSync(input,bundle,{mode:0o600});report={transport:"REAL_HTTP",status:"PASS",bundleBytes:bundle.length};}
 catch(error){report={transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:error.code||error.message};process.exitCode=3;}
}else if(mode==="--replay"){
 const bytes=fs.readFileSync(input),selected=JSON.parse(fs.readFileSync(configFile||path.join(path.dirname(input),"firebase-effective.json"),"utf8"));
 const source=approvedHttpConexionSource(selected.source),raw=bytes[0]===123?Buffer.from(JSON.parse(bytes).catalogBase64,"base64"):bytes;
 const expected=packHttpConexionCatalog(raw,selected.password),worker=JSON.parse(fs.readFileSync(workerFile,"utf8"));
 const lookup=dns.lookup,request=https.request,get=httpConexionResolver.get;let calls=0;
 try{
  httpConexionResolver.get=async()=>({source,password:selected.password});dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  https.request=(url,o,callback)=>{assert.equal(url.origin+url.pathname,source);assert.equal(o.method,"GET");assert.equal(o.headers.Authorization,undefined);assert.equal(o.rejectUnauthorized,true);
   const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{calls++;const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};callback(res);res.emit("data",raw);res.emit("end");});return req;
  };
  const bundle=await downloadVpnCatalog("http-conexion");assert.deepEqual(bundle,expected);process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  const response=await fetchWorker("server-vpn",{providerId:"http-conexion",dataBase64:bundle.toString("base64")},{workerToken:"synthetic-replay-token"},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await response.json()).structuredJson,worker.structuredJson);
  report={transport:"SIMULATED_HTTP_REAL_CONFIG_PAIR_AND_BYTES",status:"PASS",calls,bytes:raw.length,bundleBytes:bundle.length,wholeWorkerContractEqual:true,version:worker.structuredJson.Version,servers:worker.structuredJson.Servers.length};
 }finally{dns.lookup=lookup;https.request=request;httpConexionResolver.get=get;}
}else throw Error("Choose --real or --replay");
console.log(JSON.stringify(report));
