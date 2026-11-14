import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {readFileSync} from "node:fs";
import {gunzipSync} from "node:zlib";
import {catalog,iconFor,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {createThailandResolver,approvedThailandSource,thailandResolver} from "../lib/thailand-firebase.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const source="https://globalvpn.uk/global_admin/api/server?package_name=thailand.vpn.globalvpn";
function enable(t){const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});}
test("live providers, original PNGs, connected supplied AR PRO, monotonic versions and independent switches",t=>{
 enable(t);for(const id of ["thailand-vpn","kham-vpn"]){
  assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));assert(catalog().apps.find(x=>x.id===id).decodeEnabled);
  assert.equal(iconFor(id).mimeType,"image/png");
  assert.equal(catalog({availability:{[id]:false}}).apps.find(x=>x.id===id).decodeEnabled,false);
  assert.equal(catalog({methodStates:{[id]:{maintenance:true}}}).apps.find(x=>x.id===id).decodeEnabled,false);
 }
 assert.equal(catalog({availability:{"ar-pro-vpn":true}}).apps.find(x=>x.id==="ar-pro-vpn").decodeEnabled,true);
 assert.equal(iconFor("ar-pro-vpn").mimeType,"image/png");assert(providerIds().includes("ar-pro-vpn"));
 assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
});
test("Firebase validates original source, caches successful resolution and deletes transient installation",async()=>{
 const resolver=createThailandResolver();let calls=0,deleteCalls=0;
 const request=async(url,o)=>{calls++;
  if(o.method==="DELETE"){deleteCalls++;assert.match(o.headers.Authorization,/^FIS_v2 /);return Buffer.alloc(0);}
  if(url.endsWith("/installations")){
   const body=JSON.parse(gunzipSync(o.body));assert.equal(body.appId.includes(":android:"),true);
   return Buffer.from(JSON.stringify({fid:"a".repeat(22),authToken:{token:"fictional-token"},refreshToken:"fictional-refresh"}));
  }
  assert.equal(JSON.parse(o.body).packageName,"thailand.vpn.globalvpn");
  return Buffer.from(JSON.stringify({entries:{serverUrl:"https://globalvpn.uk/global_admin/api/"}}));
 };
 const results=await Promise.all([resolver.get(request),resolver.get(request)]);assert.equal(results[0].source,source);
 await resolver.get(request);assert.equal(calls,3);assert.equal(deleteCalls,1);
 for(const bad of ["http://globalvpn.uk/global_admin/api/","https://127.0.0.1/","https://globalvpn.uk.evil.test/global_admin/api/","https://globalvpn.uk/global_admin/api/?x=1"])
  assert.throws(()=>approvedThailandSource(bad));
});
test("Firebase failed resolution deletes tokens and has no old/default-source fallback",async()=>{
 const resolver=createThailandResolver();let deleted=0,calls=0;
 const request=async(url,o)=>{calls++;if(o.method==="DELETE"){deleted++;return Buffer.alloc(0);}
  if(url.endsWith("/installations"))return Buffer.from(JSON.stringify({fid:"a".repeat(22),authToken:{token:"fictional"},refreshToken:"fictional"}));
  return Buffer.from(JSON.stringify({entries:{serverUrl:"https://127.0.0.1/"}}));};
 await assert.rejects(()=>resolver.get(request));assert.equal(deleted,1);
 const before=calls;await assert.rejects(()=>resolver.get(request));assert.equal(calls,before);
});
for(const [id,url,agent] of [["thailand-vpn",source,"okhttp/4.12.0"],["kham-vpn","https://pukangvpn.xyz/khamvpn/Config.json","okhttp/4.12.0"]])test(id+" fixed GET over pinned TLS, redirects/private DNS rejected",async t=>{
 enable(t);let redirect=false,address="93.184.216.34",calls=0;
 t.mock.method(thailandResolver,"get",async()=>({source}));
 t.mock.method(dns,"lookup",async()=>[{address,family:4}]);
 t.mock.method(https,"request",(u,o,callback)=>{calls++;assert.equal(u.href,url);assert.equal(o.method,"GET");
  assert.equal(o.headers["User-Agent"],agent);assert.equal(o.rejectUnauthorized,true);assert.equal(o.headers.Authorization,undefined);
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const r=new EventEmitter();r.resume=()=>{};r.statusCode=redirect?302:200;r.headers=redirect?{location:url+"/evil"}:{};
   callback(r);if(!redirect){r.emit("data",Buffer.from("fictional"));r.emit("end");}});return req;});
 assert.equal((await downloadVpnCatalog(id)).toString(),"fictional");redirect=true;
 await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});address="127.0.0.1";const before=calls;
 await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,before);
});
test("gateway requires complete matching schema and retains all unknown fields",async t=>{
 const old=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(old===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=old;});
 for(const [id,path] of [["thailand-vpn","thailand.vpn.globalvpn/3"],["kham-vpn","com.khamvpn.net/24"]]){
  const doc=JSON.parse(readFileSync(new URL("../../../analysis/"+path+"/tests/fixtures/vectors.json",import.meta.url))).plain;
  const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:id,rawText:JSON.stringify(doc),structuredJson:doc,isPartial:false,warnings:[],exporterCertified:false};
  const call=r=>fetchWorker("server-vpn",{providerId:id},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(r)});
  assert.deepEqual((await(await call(good)).json()).structuredJson,doc);
  for(const bad of [{...good,isPartial:true},{...good,providerId:"other"},{...good,rawText:"<html/>"},{...good,structuredJson:{...doc,unknown:[]}}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
  const bad={...doc,Servers:[{}]};await assert.rejects(()=>call({...good,rawText:JSON.stringify(bad),structuredJson:bad}),/INVALID_WORKER_RESULT/);
 }
});
