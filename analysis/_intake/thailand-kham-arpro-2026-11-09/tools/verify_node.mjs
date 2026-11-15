/** Actual Node transport attempt plus explicitly simulated HTTP/real-result replay. */
import {readFileSync,writeFileSync} from "node:fs";
import {join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import assert from "node:assert/strict";
const root=fileURLToPath(new URL("../../../../",import.meta.url));
const {downloadVpnCatalog}=await import(join(root,"cloud/web/lib/server-vpn-provider.mjs"));
const {thailandResolver}=await import(join(root,"cloud/web/lib/thailand-firebase.mjs"));
const {fetchWorker}=await import(join(root,"cloud/web/lib/c3-gateway.mjs"));
const privateRoot=resolve(process.argv[2]);
process.env.CLOUD_SERVER_VPN_ENABLED="true";process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
const cases=[["thailand-vpn","thailand.vpn.globalvpn",3],["kham-vpn","com.khamvpn.net",24]];
for(const [id,pkg,build] of cases){
 const proof={actualNodeTransport:null,replayHttpSimulated:true,replayUsesRealBytesAndChildWorkerResult:true};
 try{const data=await downloadVpnCatalog(id);proof.actualNodeTransport={status:"received",bytes:data.length};}
 catch(error){proof.actualNodeTransport={status:"failed",code:error.code||"LOCAL_ERROR"};}
 const wire=readFileSync(join(privateRoot,pkg,"catalog.wire"));
 const worker=JSON.parse(readFileSync(join(privateRoot,pkg,"worker-result.json")));
 const lookup=dns.lookup,request=https.request,get=thailandResolver.get;
 try{
  dns.lookup=async()=>[{address:"93.184.216.34",family:4}];
  thailandResolver.get=async()=>({source:"https://globalvpn.uk/global_admin/api/server?package_name=thailand.vpn.globalvpn"});
  https.request=(url,options,callback)=>{
   const req=new EventEmitter();req.destroy=()=>{};
   req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.resume=()=>{};res.statusCode=200;res.headers={};callback(res);res.emit("data",wire);res.emit("end");});return req;
  };
  assert.deepEqual(await downloadVpnCatalog(id),wire);
  const result=await fetchWorker("server-vpn",{providerId:id},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(worker)});
  assert.deepEqual((await result.json()).structuredJson,worker.structuredJson);proof.replayPassed=true;
 }finally{dns.lookup=lookup;https.request=request;thailandResolver.get=get;}
 writeFileSync(join(root,"analysis",pkg,String(build),"generated/node-validation.json"),JSON.stringify(proof,null,2)+"\n");
 console.log(id,JSON.stringify(proof));
}
