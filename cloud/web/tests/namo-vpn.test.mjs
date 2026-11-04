import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {mkdtemp,rm,readFile} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {catalog,iconFor,CATALOG_VERSION,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {updateProvider,providerAllowed,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";

const source="https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newnamo.json";
const expected=JSON.parse(fs.readFileSync(new URL("../../../analysis/com.appxrayservice.namovpn/35/tests/fixtures/expected.json",import.meta.url)));
function enabled(t){
 for(const key of ["CLOUD_API_ENABLED","CLOUD_SERVER_VPN_ENABLED"]){
  const prev=process.env[key];process.env[key]="true";
  t.after(()=>{if(prev===undefined)delete process.env[key];else process.env[key]=prev;});
 }
}
function network(t,{data=Buffer.from("synthetic envelope"),location,check=()=>{}}={}){
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(url,options,callback)=>{
  check(url,options);const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.statusCode=location?302:200;res.headers=location?{location}:{};res.resume=()=>{};
   callback(res);if(!location){res.emit("data",data);res.emit("end");}
  });return req;
 });
}
function icons(t){
 const read=fs.readFileSync,png=read(new URL("../public/server-vpn-icons/namo-vpn.png",import.meta.url));
 // Other apps' raster contents are outside this provider-specific test.
 t.mock.method(fs,"readFileSync",(path,...args)=>String(path).includes("server-vpn-icons")?png:read(path,...args));
 syncBuiltinESMExports();t.after(()=>{t.mock.restoreAll();syncBuiltinESMExports();});return png;
}
test("NAMO original public updater GET uses its original OkHttp agent and fixed TLS destination",async t=>{
 enabled(t);let calls=0;
 network(t,{check:(url,options)=>{
  calls++;assert.equal(url.href,source);assert.equal(options.method,"GET");
  assert.equal(options.headers["User-Agent"],"okhttp/5.3.2");
  assert.equal(options.headers.Authorization,undefined);assert.equal(options.rejectUnauthorized,true);
  assert.equal(options.headers["Accept-Encoding"],"identity");
 }});
 assert.equal((await downloadVpnCatalog("namo-vpn")).toString(),"synthetic envelope");
 await assert.rejects(()=>downloadVpnCatalog("namo-vpn","https://example.org/"),{code:"UNSUPPORTED_FORMAT"});
 assert.equal(calls,1);
});
test("NAMO rejects private DNS and all redirects",async t=>{
 enabled(t);let calls=0;
 network(t,{location:"https://raw.githubusercontent.com/other/repo/main/other",check:()=>{calls++;}});
 await assert.rejects(()=>downloadVpnCatalog("namo-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,1);
 t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
 await assert.rejects(()=>downloadVpnCatalog("namo-vpn"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,1);
});
test("NAMO original PNG and public directory preserve metadata-only availability",t=>{
 enabled(t);const png=icons(t);
 assert(providerIds().includes("namo-vpn"));assert(PUBLIC_PROVIDER_IDS.includes("namo-vpn"));
 assert.equal(CATALOG_VERSION,68);assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
 const doc=catalog(),app=doc.apps.find(x=>x.id==="namo-vpn");
 assert.equal(doc.apps.length,64);assert.equal(app.name,"NAMO VPN");assert.equal(app.decodeEnabled,true);
 assert.equal(app.iconSha256,"1b40b83a4ace052dfee16f56369143fc71b79c2dd34454ca4eb541d59f312f7e");
 assert.equal(iconFor(app.id).bytes.length,25421);assert.equal(png.length,25421);
 assert(!JSON.stringify(app).includes("https://"));assert.equal(doc.formats.length,256);
 assert.equal(catalog({availability:{"namo-vpn":false}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
 assert.equal(catalog({methodStates:{"namo-vpn":{maintenance:true}}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
});
test("NAMO switch does not reset existing operator choices",async t=>{
 enabled(t);icons(t);const root=await mkdtemp(join(tmpdir(),"alsaher-controls-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
 await updateProvider("netcol-vpn",false,env,{root});await updateProvider("namo-vpn",false,env,{root});
 assert.equal(await providerAllowed("namo-vpn",env,{root}),false);
 await updateProvider("namo-vpn",true,env,{root});
 assert.equal(await providerAllowed("namo-vpn",env,{root}),true);
 assert.equal(await providerAllowed("netcol-vpn",env,{root}),false);
 assert(!String(await readFile(join(root,"switches.json"))).includes(source));
});
test("NAMO gateway requires complete matching JSON and rejects malformed/partial lists",async t=>{
 const prev=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(prev===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=prev;});
 const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"namo-vpn",structuredJson:expected,
  rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false};
 const call=x=>fetchWorker("server-vpn",{providerId:"namo-vpn"},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(x)});
 assert.deepEqual((await (await call(good)).json()).structuredJson,expected);
 for(const bad of [{...good,isPartial:true},{...good,providerId:"zig-tunnel"},
  {...good,rawText:JSON.stringify({...expected,Version:"changed"})}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
 for(const change of [d=>d.Servers=[],d=>delete d.Networks,d=>d.Networks=[{PayloadName:1}],d=>d.Message=[]]){
  const doc=structuredClone(expected);change(doc);
  await assert.rejects(()=>call({...good,structuredJson:doc,rawText:JSON.stringify(doc)}),/INVALID_WORKER_RESULT/);
 }
});
