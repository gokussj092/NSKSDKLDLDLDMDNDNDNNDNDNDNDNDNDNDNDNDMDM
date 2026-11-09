import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {catalog,iconFor,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {POST as iconRoute} from "../app/api/v1/server-vpn/icon/route.js";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const cases=[
 ["opentunnel-ssh","https://api.roosterkid.com/api/opentunnel/servers/","SP-DECODE/1.0","image/png","2687863c67e82e2fcff500ffd34d4fff6ec5b59662a4db6eb96650ed6aca8c98"],
 ["md-proxy-vpn","https://strongteam.co/api/ultrasystem/ultrav3.txt","MD PROXY VPN","image/webp","80d2b61d218690948a2b7e510668c91df69f828a1cfab9d51ac1c3c9592e71e1"]
];
function enabled(t){const before=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";t.after(()=>{if(before===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=before;});}
test("two new identities, exact original icons, and explicit OpenTunnel files",async t=>{
 enabled(t);const doc=catalog();assert(CATALOG_VERSION>=79);assert(doc.apps.length>=73);
 assert.equal(doc.formats.find(x=>x.suffix==="tnl").cloudSupported,true);
 for(const [id,,,mime,sha] of cases){
  const app=doc.apps.find(x=>x.id===id);assert(app?.decodeEnabled);assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));
  assert.equal(app.iconMimeType,mime);assert.equal(iconFor(id).sha256,sha);assert.equal(app.iconSha256,sha);
  const response=await iconRoute(new Request("https://example.invalid/api/v1/server-vpn/icon",{method:"POST",body:JSON.stringify({id})}));
  assert.equal(response.status,200);const icon=await response.json();assert.equal(icon.mimeType,mime);assert.equal(icon.sha256,sha);
  assert(!JSON.stringify(app).includes("strongteam"));assert(!JSON.stringify(app).includes("roosterkid"));
 }
 assert.match(doc.apps.find(x=>x.id==="opentunnel-ssh").name,/Servidores SSH/);
});
for(const [id,source,agent] of cases)test(id+" uses a single fixed GET; no account generation or bundled second request",async t=>{
 enabled(t);let address="93.184.216.34",redirect=false,calls=0;
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,new URL(source).hostname);return [{address,family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  calls++;assert.equal(url.href,source);assert.equal(options.method,"GET");assert.equal(options.headers["User-Agent"],agent);assert.equal(options.headers["Accept-Encoding"],"identity");assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.resume=()=>{};res.statusCode=redirect?302:200;res.headers=redirect?{location:source+"other"}:{};
   callback(res);if(!redirect){res.emit("data",Buffer.from("synthetic-response"));res.emit("end");}
  });return req;
 });
 assert.equal((await downloadVpnCatalog(id)).toString(),"synthetic-response");assert.equal(calls,1);
 redirect=true;await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});
 address="127.0.0.1";const before=calls;await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,before);
});
test("maintenance and operator availability apply separately",t=>{
 enabled(t);for(const options of [{availability:{"opentunnel-ssh":false}},{methodStates:{"opentunnel-ssh":{maintenance:true}}}]){
  const apps=catalog(options).apps;assert.equal(apps.find(x=>x.id==="opentunnel-ssh").decodeEnabled,false);assert.equal(apps.find(x=>x.id==="md-proxy-vpn").decodeEnabled,true);
 }
});
test("gateway accepts complete matching documents and rejects identity, schema and JSON disagreement",async t=>{
 const before=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(before===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=before;});
 for(const [id,doc] of [["opentunnel-ssh",{status:200,count:1,servers:[{hostname:"ssh.example.invalid"}]}],["md-proxy-vpn",{Version:"synthetic",Servers:[{Name:"a"}],Networks:[{Name:"b"}]}]]){
  const result={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:id,rawText:JSON.stringify(doc),structuredJson:doc,isPartial:false,warnings:[],exporterCertified:false};
  const call=r=>fetchWorker("server-vpn",{providerId:id},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(r)});
  assert.deepEqual((await (await call(result)).json()).structuredJson,doc);
  for(const bad of [{...result,providerId:"ultra-tunnel"},{...result,isPartial:true},{...result,structuredJson:{...doc,extra:true}},{...result,rawText:"<html/>"}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
  const invalid=id==="opentunnel-ssh"?{...doc,count:2}:{...doc,Networks:[{}]};
  await assert.rejects(()=>call({...result,rawText:JSON.stringify(invalid),structuredJson:invalid}),/INVALID_WORKER_RESULT/);
 }
});
