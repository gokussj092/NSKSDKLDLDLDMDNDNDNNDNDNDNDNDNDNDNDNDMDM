import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {HTTP_CONEXION_SOURCE,httpConexionRequestUrl} from "../lib/http-conexion-protocol.mjs";
import {httpConexionResolver} from "../lib/http-conexion-firebase.mjs";
import {providerIds,providerEnabled,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {catalog,iconFor,CATALOG_VERSION,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {updateProvider,providerAllowed,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const source="https://raw.githubusercontent.com/soportecrisdev/Gen/main/new";
const expected=JSON.parse(fs.readFileSync(new URL("../../../analysis/com.doriaxvpn.unlimited/129/tests/fixtures/expected.json",import.meta.url)));
function enable(t){
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 t.mock.method(httpConexionResolver,"get",async()=>({source,password:"fictional-resolved-password"}));
}
function network(t,{status=200,location,data=Buffer.from("synthetic ciphertext"),check=()=>{}}={}){
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(url,options,callback)=>{
  check(url,options);const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=location?302:status;
   res.headers=location?{location}:{};res.resume=()=>{};callback(res);
   if(!location&&status===200){res.emit("data",data);res.emit("end");}
  });return req;
 });
}
test("HTTP Conexión pins the real Remote Config source and the APK nocache timestamp",()=>{
 assert.equal(HTTP_CONEXION_SOURCE,source);assert.equal(httpConexionRequestUrl(1700000000000),source+"?nocache=1700000000000");
 for(const bad of [0,-1,NaN,1.2,"1700000000000"])assert.throws(()=>httpConexionRequestUrl(bad),/INVALID_PROVIDER_TIMESTAMP/);
});
test("HTTP Conexión sends the exact original GET agent/cache headers over pinned TLS",async t=>{
 enable(t);t.mock.method(Date,"now",()=>1700000000000);let calls=0;
 network(t,{check:(url,o)=>{calls++;assert.equal(url.href,source+"?nocache=1700000000000");
  assert.equal(o.method,"GET");assert.equal(o.rejectUnauthorized,true);assert.equal(o.headers["User-Agent"],"HTTP-Conexion-VPN/3.0");
  assert.equal(o.headers.Accept,"*/*");assert.equal(o.headers["Cache-Control"],"no-cache, no-store, must-revalidate");
  assert.equal(o.headers.Pragma,"no-cache");assert.equal(o.headers.Expires,"0");
  assert.equal(o.headers["Accept-Encoding"],"identity");assert.equal(o.headers.Authorization,undefined);
 }});
 const envelope=JSON.parse((await downloadVpnCatalog("http-conexion")).toString());
 assert.equal(envelope.kind,"spdecode-http-conexion-config-v1");
 assert.equal(Buffer.from(envelope.catalogBase64,"base64").toString(),"synthetic ciphertext");
 assert.equal(Buffer.from(envelope.passwordBase64,"base64").toString(),"fictional-resolved-password");
 await assert.rejects(()=>downloadVpnCatalog("http-conexion","https://example.org/"),{code:"UNSUPPORTED_FORMAT"});assert.equal(calls,1);
});
test("HTTP Conexión rejects private DNS and every redirect",async t=>{
 enable(t);let calls=0;network(t,{location:source+"/other",check:()=>calls++});
 await assert.rejects(()=>downloadVpnCatalog("http-conexion"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,1);
 t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
 await assert.rejects(()=>downloadVpnCatalog("http-conexion"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls,1);
});
test("HTTP Conexión never hides a current-source 404 with the obsolete default or an asset",async t=>{
 enable(t);let calls=0;network(t,{status:404,check:url=>{calls++;assert.equal(url.pathname,"/soportecrisdev/Gen/main/new");}});
 await assert.rejects(()=>downloadVpnCatalog("http-conexion"),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.equal(calls,1);
});
test("HTTP Conexión original large PNG and availability retain all other public methods",()=>{
 assert(providerIds().includes("http-conexion"));assert(PUBLIC_PROVIDER_IDS.includes("http-conexion"));
 assert(providerEnabled("http-conexion",{CLOUD_SERVER_VPN_ENABLED:"true"}));
 assert.equal(CATALOG_VERSION,71);assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
 const doc=catalog(),app=doc.apps.find(x=>x.id==="http-conexion");assert.equal(doc.apps.length,65);assert.equal(doc.formats.length,256);
 assert.equal(app.name,"HTTP Conexión");assert.equal(app.iconSha256,"5b0e24bddf371bd0256c564c221c0fe87b8dc1b23340e51de6e224386f83b41a");
 assert.equal(iconFor(app.id).bytes.length,449874);assert(!JSON.stringify(app).includes("https://"));
 assert.equal(catalog({availability:{"http-conexion":false}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
});
test("HTTP Conexión switch preserves the operator's existing choices",async t=>{
 enable(t);const root=await mkdtemp(join(tmpdir(),"conexion-controls-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
 await updateProvider("netcol-vpn",false,env,{root});await updateProvider("http-conexion",false,env,{root});
 assert.equal(await providerAllowed("http-conexion",env,{root}),false);
 await updateProvider("http-conexion",true,env,{root});assert.equal(await providerAllowed("http-conexion",env,{root}),true);
 assert.equal(await providerAllowed("netcol-vpn",env,{root}),false);
});
test("HTTP Conexión gateway requires whole matching nonpartial JSON",async t=>{
 const old=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
 t.after(()=>{if(old===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=old;});
 const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"http-conexion",structuredJson:expected,
  rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false};
 const call=x=>fetchWorker("server-vpn",{providerId:"http-conexion"},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(x)});
 assert.deepEqual((await(await call(good)).json()).structuredJson,expected);
 for(const bad of [{...good,isPartial:true},{...good,providerId:"namo-vpn"},
  {...good,rawText:JSON.stringify({...expected,Version:"mismatch"})}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
 for(const change of [d=>d.Servers=[],d=>d.Servers=[{}],d=>d.ReleaseNotes={}]){
  const doc=structuredClone(expected);change(doc);await assert.rejects(()=>call({...good,structuredJson:doc,rawText:JSON.stringify(doc)}),/INVALID_WORKER_RESULT/);
 }
});
