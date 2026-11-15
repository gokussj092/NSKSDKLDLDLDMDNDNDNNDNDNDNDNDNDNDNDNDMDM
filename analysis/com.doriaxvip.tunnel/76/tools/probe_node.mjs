/** Real transport, or explicitly simulated HTTP carrying complete real catalog bytes. */
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHash} from "node:crypto";
import {downloadVpnCatalog} from "../../../../cloud/web/lib/server-vpn-provider.mjs";
import {fetchWorker} from "../../../../cloud/web/lib/c3-gateway.mjs";

process.env.CLOUD_SERVER_VPN_ENABLED="true";
const [mode,directory]=process.argv.slice(2),id="genis-vpn";
const source="https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis";
let report;
if(mode==="--real"){
  try{
    const bytes=await downloadVpnCatalog(id);
    fs.writeFileSync(directory+"/node.enc",bytes,{mode:0o600});
    report={transport:"REAL_HTTP",status:"PASS",bytes:bytes.length,sha256:createHash("sha256").update(bytes).digest("hex")};
  }catch(error){report={transport:"REAL_HTTP",status:"NETWORK_UNAVAILABLE",code:error.code||error.message};process.exitCode=3;}
}else if(mode==="--replay"){
  const bytes=fs.readFileSync(directory+"/remote.enc");
  const worker=JSON.parse(fs.readFileSync(directory+"/worker.json","utf8"));
  const lookup=dns.lookup,request=https.request;let calls=0;
  try{
    dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
    https.request=(url,options,callback)=>{
      assert.equal(url.href,source);assert.equal(options.method,"GET");assert.equal(options.rejectUnauthorized,true);
      assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0 (Linux; U; Android 14)");
      const request=new EventEmitter();request.destroy=()=>{};
      request.end=()=>queueMicrotask(()=>{
        calls++;const response=new EventEmitter();response.statusCode=200;response.headers={};response.resume=()=>{};
        callback(response);response.emit("data",bytes);response.emit("end");
      });return request;
    };
    const downloaded=await downloadVpnCatalog(id);assert.deepEqual(downloaded,bytes);
    process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
    const response=await fetchWorker("server-vpn",{providerId:id,dataBase64:downloaded.toString("base64")},
      {workerToken:"synthetic-replay-internal"},{fetchImpl:async()=>Response.json(worker)});
    assert.deepEqual((await response.json()).structuredJson,worker.structuredJson);
    report={transport:"SIMULATED_HTTP_REAL_BYTES",status:"PASS",calls,wholeWorkerContractEqual:true,
      version:worker.structuredJson.Version,servers:worker.structuredJson.Servers.length};
  }finally{dns.lookup=lookup;https.request=request;}
}else throw Error("Choose --real or --replay");
fs.writeFileSync(directory+"/node"+mode.replace("--","-")+".json",JSON.stringify(report,null,2)+"\n",{mode:0o600});
console.log(JSON.stringify(report));
