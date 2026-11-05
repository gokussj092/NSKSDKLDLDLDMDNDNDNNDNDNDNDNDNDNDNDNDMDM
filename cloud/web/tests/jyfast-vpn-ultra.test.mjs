import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import {EventEmitter} from "node:events";
import {mkdtemp,rm,writeFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {downloadVpnCatalog,providerIds} from "../lib/server-vpn-provider.mjs";
import {packPairedVpnCatalogs} from "../lib/paired-vpn-catalogs.mjs";
import {catalog,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {providerOverview,updateProvider} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";

function enabled(t){
 const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;});
}
function transport(t,{address="93.184.216.34",status=200}={}){
 enabled(t);let calls=0;const seen=[];
 t.mock.method(dns,"lookup",async host=>{
  assert.equal(host,"dev.jenrri.shop");return [{address,family:4}];
 });
 t.mock.method(https,"request",()=>{throw Error("unexpected HTTPS target");});
 t.mock.method(http,"request",(url,options,callback)=>{
  calls++;seen.push(url.href);
  assert.equal(url.origin,"http://dev.jenrri.shop:85");
  assert.equal(url.pathname,"/ignix_update.php");
  assert(["?cfg=free","?cfg=premium"].includes(url.search));
  assert.equal(options.headers["X-IGNIX-SIG"],"10c7440b8feac5cee6a54959e7599ff26bd27153");
  assert.equal(options.headers["Accept-Encoding"],"identity");
  assert(options.timeout>0 && options.timeout<=10000);
  options.lookup(url.hostname,{},(error,ip,family)=>{
   assert.equal(error,null);assert.equal(ip,address);assert.equal(family,4);
  });
  const request=new EventEmitter();request.destroy=()=>{};
  request.end=()=>queueMicrotask(()=>{
   const response=new EventEmitter();response.resume=()=>{};
   response.statusCode=status;
   response.headers=status===302?{location:url.origin+"/other"+url.search}:{};
   callback(response);
   if(status===200){response.emit("data",Buffer.from(url.search));response.emit("end");}
  });return request;
 });return {seen,calls:()=>calls};
}
test("JyFast pins both exact APK sources, port 85, certificate header and public DNS",async t=>{
 const mock=transport(t);
 assert.equal((await downloadVpnCatalog("jyfast-vpn-ultra")).toString(),"?cfg=free");
 assert.equal((await downloadVpnCatalog("jyfast-vpn-ultra","premium")).toString(),"?cfg=premium");
 assert.equal(mock.calls(),2);
 assert(providerIds().includes("jyfast-vpn-ultra"));
 for(const source of ["custom","servers","http://127.0.0.1/","../free"])
  await assert.rejects(()=>downloadVpnCatalog("jyfast-vpn-ultra",source),{code:"UNSUPPORTED_FORMAT"});
 assert.equal(mock.calls(),2);
});
test("JyFast refuses private DNS before any HTTP request",async t=>{
 const mock=transport(t,{address:"127.0.0.1"});
 await assert.rejects(()=>downloadVpnCatalog("jyfast-vpn-ultra"),{code:"REMOTE_NETWORK_DENIED"});
 assert.equal(mock.calls(),0);
});
test("JyFast refuses every redirect without a stale or cross-origin fallback",async t=>{
 const mock=transport(t,{status:302});
 await assert.rejects(()=>downloadVpnCatalog("jyfast-vpn-ultra"),{code:"REMOTE_NETWORK_DENIED"});
 assert.equal(mock.calls(),1);
});
test("JyFast respects the deployment switch before DNS",async t=>{
 enabled(t);process.env.CLOUD_SERVER_VPN_ENABLED="false";
 t.mock.method(dns,"lookup",()=>{throw Error("unexpected network");});
 await assert.rejects(()=>downloadVpnCatalog("jyfast-vpn-ultra"),{code:"REMOTE_NOT_CONFIGURED"});
});
test("paired JyFast catalogs require both complete sources and preserve their bytes",()=>{
 const free=Buffer.from("first source"),premium=Buffer.from("second source");
 const b=JSON.parse(packPairedVpnCatalogs("jyfast-vpn-ultra",{free,premium}));
 assert.equal(b.kind,"spdecode-jyfast-vpn-ultra-catalogs-v1");
 assert.equal(Buffer.from(b.catalogs.free,"base64").toString(),free.toString());
 assert.equal(Buffer.from(b.catalogs.premium,"base64").toString(),premium.toString());
 assert.throws(()=>packPairedVpnCatalogs("jyfast-vpn-ultra",{free}),{code:"REMOTE_RESPONSE_INVALID"});
});
test("public metadata contains the original icon and honors per-provider availability",()=>{
 const app=catalog({availability:{"jyfast-vpn-ultra":true}}).apps.find(x=>x.id==="jyfast-vpn-ultra");
 assert.equal(CATALOG_VERSION,73);assert.equal(catalog().apps.length,67);
 assert.equal(app.name,"JyFast VPN Ultra");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"05e176023754019f84135e0247d0db91370a450536ddbc7b035c626e0a094ae8");
 assert.equal(catalog({availability:{"jyfast-vpn-ultra":false}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
 assert.deepEqual(Object.keys(app).sort(),["decodeEnabled","iconMimeType","iconSha256","id","maintenance","methodRevision","name"]);
});
test("JyFast admin control preserves an existing disabled provider and advances the version",async t=>{
 const root=await mkdtemp(join(tmpdir(),"jyfast-control-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
 await writeFile(join(root,"switches.json"),JSON.stringify({version:250000000,disabled:["http-jireh"]}));
 const before=await providerOverview(env,{root});assert.equal(before.providers.find(x=>x.id==="jyfast-vpn-ultra").name,"JyFast VPN Ultra");
 const after=await updateProvider("jyfast-vpn-ultra",false,env,{root});
 assert(after.catalogVersion>before.catalogVersion);
 assert.equal(after.providers.find(x=>x.id==="http-jireh").enabled,false);
 assert.equal(after.providers.find(x=>x.id==="jyfast-vpn-ultra").enabled,false);
});
test("worker contract accepts both full modes and rejects omitted or mismatched documents",async t=>{
 const previous=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
 const doc={provider:"jyfast-vpn-ultra",complete:true,catalogs:{free:{Version:"1",Servers:[{Name:"synthetic free"}]},premium:{Version:"1",Servers:[{Name:"synthetic premium"}]}}};
 const result={status:"success",kind:"vpn_catalog",providerId:"jyfast-vpn-ultra",isPartial:false,rawText:JSON.stringify(doc),structuredJson:doc};
 const call=body=>fetchWorker("server-vpn",{providerId:"jyfast-vpn-ultra"},{workerToken:"synthetic"},{fetchImpl:async()=>Response.json(body)});
 assert.equal((await call(result)).status,200);
 for(const bad of [
  {...result,structuredJson:{...doc,complete:false}},
  {...result,rawText:JSON.stringify({...doc,catalogs:{free:doc.catalogs.free}})},
  {...result,isPartial:true},
  {...result,providerId:"http-jireh"},
 ])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
 for(const free of [{Servers:[{Name:"x"}]},{Version:"1",Servers:[]},{Version:"1",Servers:[null]},{Version:"1",Servers:[{Name:7}]}]){
  const malformed={...doc,catalogs:{...doc.catalogs,free}};
  await assert.rejects(()=>call({...result,rawText:JSON.stringify(malformed),structuredJson:malformed}),/INVALID_WORKER_RESULT/);
 }
});
