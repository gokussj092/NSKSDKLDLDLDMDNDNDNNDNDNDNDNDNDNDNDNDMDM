import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {mkdtemp,rm,readFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {CATNET_SOURCE,CATNET_PREFLIGHT,catnetHeaders} from "../lib/catnet-protocol.mjs";
import {downloadVpnCatalog,providerIds} from "../lib/server-vpn-provider.mjs";
import {catalog,iconFor,CATALOG_VERSION,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {updateProvider,providerAllowed,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const fixture=new URL("../../../analysis/net.catnet.vpn/27/tests/fixtures/",import.meta.url);
const raw=fs.readFileSync(new URL("servers.json",fixture));const doc=JSON.parse(raw);
const preflight=fs.readFileSync(new URL("preflight.json",fixture));
function enabled(t){
 const previous=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;});
}
function network(t,answers=[preflight,raw]){
 const calls=[];
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(url,options,callback)=>{
  calls.push({url,options});const value=answers[calls.length-1];const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.statusCode=value?.status??200;res.headers=value?.headers??{};res.resume=()=>{};
   callback(res);if(res.statusCode===200){res.emit("data",Buffer.isBuffer(value)?value:Buffer.from(value?.body??""));res.emit("end");}
  });return req;
 });return calls;
}
test("CATNET performs original preflight and server GET with consistent real installation metadata",async t=>{
 enabled(t);const calls=network(t);assert.deepEqual(await downloadVpnCatalog("catnet-vpn"),raw);
 assert.deepEqual(calls.map(x=>x.url.href),[CATNET_PREFLIGHT,CATNET_SOURCE]);
 const first=calls[0].options.headers,second=calls[1].options.headers;
 assert.equal(first["X-XJ-Installation-Id"],second["X-XJ-Installation-Id"]);
 assert.match(first["X-XJ-Installation-Id"],/^[a-f0-9-]{36}$/);
 for(const {options} of calls){
  assert.equal(options.method,"GET");assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  assert.equal(options.headers["User-Agent"],"okhttp/4.12.0");assert.equal(options.headers["Accept-Encoding"],"identity");
  assert.equal(options.headers["X-XJ-Version-Code"],"27");assert.equal(options.headers["X-App-Key"],"pussy_vpn");
  assert.equal(options.headers["X-XJ-App-Package"],"net.catnet.vpn");
  assert.equal(options.headers.Authorization,undefined);assert.equal(options.headers["X-XJ-Integrity-Token"],undefined);
  assert.equal(options.headers["X-XJ-Integrity-Session"],undefined);
 }
 assert.notEqual(catnetHeaders()["X-XJ-Installation-Id"],first["X-XJ-Installation-Id"]);
});
test("CATNET does not fetch catalogs when legitimate Play verification becomes required or unspecified",async t=>{
 enabled(t);
 for(const required of [true,null,undefined,0,"false"]){
  const calls=network(t,[Buffer.from(JSON.stringify({success:true,data:{integrity_required:required}}))]);
  await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_NOT_CONFIGURED"});assert.equal(calls.length,1);
 }
});
test("CATNET rejects maintenance, invalid preflight and HTML instead of treating HTTP200 as catalog",async t=>{
 enabled(t);
 for(const value of [Buffer.from("<html>Site Unavailable</html>"),Buffer.from("{}"),Buffer.from("[]"),Buffer.from([255])]){
  const calls=network(t,[value]);await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_RESPONSE_INVALID"});assert.equal(calls.length,1);
 }
 const calls=network(t,[Buffer.from('{"success":true,"data":{"maintenance":true,"integrity_required":false}}')]);
 await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.equal(calls.length,1);
});
test("CATNET rejects redirect and revalidates public DNS before each fixed request",async t=>{
 enabled(t);
 for(const answers of [[{status:302,headers:{location:"https://example.org/"}}],[preflight,{status:302,headers:{location:CATNET_SOURCE}}]]){
  const calls=network(t,answers);await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls.length,answers.length);
 }
 const calls=network(t);let lookups=0;
 t.mock.method(dns,"lookup",async()=>[{address:++lookups===1?"93.184.216.34":"127.0.0.1",family:4}]);
 await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls.length,1);
});
test("CATNET exposes only servers and rejects arbitrary URL, payload or credential-selected sources before DNS",async t=>{
 enabled(t);const calls=network(t);
 for(const source of ["payloads","xray_payloads","https://example.org/","accounts",null]){
  await assert.rejects(()=>downloadVpnCatalog("catnet-vpn",source),{code:"UNSUPPORTED_FORMAT"});
 }
 assert.equal(calls.length,0);
});
test("CATNET bounds preflight and rejects bad server responses without retry or stale fallback",async t=>{
 enabled(t);
 const calls=network(t,[Buffer.alloc(65537,32)]);
 await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"),{code:"REMOTE_TOO_LARGE"});assert.equal(calls.length,1);
 for(const answer of [Buffer.from("<html>Site Unavailable</html>"),{status:403},{headers:{"content-encoding":"gzip"},body:"bad"}]){
  const later=network(t,[preflight,answer]);await assert.rejects(()=>downloadVpnCatalog("catnet-vpn"));assert.equal(later.length,2);
 }
});
test("CATNET original launcher, public metadata, monotonic versions and availability preserve all formats",t=>{
 enabled(t);assert(providerIds().includes("catnet-vpn"));assert(PUBLIC_PROVIDER_IDS.includes("catnet-vpn"));
 assert.equal(CATALOG_VERSION,73);assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
 const values=catalog(),app=values.apps.find(x=>x.id==="catnet-vpn");
 assert.equal(values.apps.length,67);assert.equal(values.formats.length,256);assert.equal(app.name,"CATNET VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"f6d8e484d5ce00ce6c170bff16907ae3384909c147fc0d4f7ff4fdf20207d27d");
 assert.equal(iconFor(app.id).bytes.length,52811);assert(!JSON.stringify(app).includes("https://"));
 assert.equal(catalog({availability:{"catnet-vpn":false}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
 assert.equal(catalog({methodStates:{"catnet-vpn":{maintenance:true}}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
});
test("CATNET individual switch preserves previous operator decisions",async t=>{
 const root=await mkdtemp(join(tmpdir(),"catnet-controls-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
 await updateProvider("namo-vpn",false,env,{root});await updateProvider("catnet-vpn",false,env,{root});
 assert.equal(await providerAllowed("catnet-vpn",env,{root}),false);await updateProvider("catnet-vpn",true,env,{root});
 assert.equal(await providerAllowed("catnet-vpn",env,{root}),true);assert.equal(await providerAllowed("namo-vpn",env,{root}),false);
 assert(!String(await readFile(join(root,"switches.json"))).includes("pussyvpn.com"));
});
test("CATNET worker contract keeps the whole source and rejects malformed or partial success",async t=>{
 const prev=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(prev===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=prev;});
 const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"catnet-vpn",structuredJson:doc,
  rawText:JSON.stringify(doc),isPartial:false,warnings:[],exporterCertified:false};
 const call=x=>fetchWorker("server-vpn",{providerId:"catnet-vpn"},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(x)});
 assert.deepEqual((await (await call(good)).json()).structuredJson,doc);
 for(const bad of [{...good,isPartial:true},{...good,providerId:"namo-vpn"},{...good,rawText:"{}"}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
 for(const change of [d=>d.success=false,d=>d.servers=[],d=>d.servers=[{}],d=>d.message=null,d=>d.has_defaults=1,
  d=>d.def_pass_plain=null,d=>d.servers[0].id=true,d=>d.servers[0].id=0,d=>d.servers[0].ip=""]){
  const changed=structuredClone(doc);change(changed);
  await assert.rejects(()=>call({...good,structuredJson:changed,rawText:JSON.stringify(changed)}),/INVALID_WORKER_RESULT/);
 }
});
