import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {downloadVpnCatalog,providerIds} from "../lib/server-vpn-provider.mjs";
import {catalog,iconFor,CATALOG_VERSION,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {updateProvider,providerAllowed,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const id="xxpicore-tunnel",url="https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xxpicoretunnel888.hs";
const fixtures=new URL("../../../analysis/pro.xxpicore.tunnel/118/tests/fixtures/",import.meta.url);
const raw=fs.readFileSync(new URL("catalog.enc",fixtures)),doc=JSON.parse(fs.readFileSync(new URL("expected.json",fixtures)));
function enabled(t){const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});}
function network(t,answer={body:raw}){
 const calls=[];t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(target,options,callback)=>{
  calls.push({target,options});const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=answer.status??200;res.headers=answer.headers??{};res.resume=()=>{};
   callback(res);if(res.statusCode===200){res.emit("data",answer.body??raw);res.emit("end");}});return req;
 });return calls;
}
test("XXPICore uses the exact fixed public updater and bounded TLS request",async t=>{
 enabled(t);const calls=network(t);assert.deepEqual(await downloadVpnCatalog(id),raw);assert.equal(calls.length,1);
 const {target,options}=calls[0];assert.equal(target.href,url);assert.equal(options.method,"GET");
 assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
 assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0 (Linux; U; Android 14)");assert.equal(options.headers["Accept-Encoding"],"identity");assert.equal(options.headers.Authorization,undefined);
});
test("XXPICore rejects redirects, HTML and compressed responses",async t=>{
 enabled(t);
 for(const answer of [{status:302,headers:{location:url}},{body:Buffer.from("<html>Site Unavailable</html>")},{headers:{"content-encoding":"gzip"}}]){
  const calls=network(t,answer);await assert.rejects(()=>downloadVpnCatalog(id));assert.equal(calls.length,1);
 }
});
test("XXPICore rejects private DNS and client-selected sources",async t=>{
 enabled(t);const calls=network(t);
 for(const source of ["users","https://example.org/",null])await assert.rejects(()=>downloadVpnCatalog(id,source),{code:"UNSUPPORTED_FORMAT"});
 t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
 await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls.length,0);
});
test("XXPICore original icon, public metadata, versions and formats",t=>{
 enabled(t);assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));
 assert.ok(CATALOG_VERSION>=73);assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
 const value=catalog(),app=value.apps.find(x=>x.id===id);assert.equal(value.apps.length,67);assert.equal(value.formats.length,256);
 assert.equal(app.name,"XXPICore Tunnel");assert.equal(app.decodeEnabled,true);assert.equal(iconFor(id).bytes.length,78910);
 assert.equal(app.iconSha256,"e83e97346f5f7ef672a1ec85f177da0f3660579e37df2939f0a62f1a0620ba88");assert(!JSON.stringify(app).includes("https://"));
 for(const config of [{availability:{[id]:false}},{methodStates:{[id]:{maintenance:true}}}])assert.equal(catalog(config).apps.find(x=>x.id===id).decodeEnabled,false);
});
test("XXPICore operator switch preserves existing disabled providers",async t=>{
 const root=await mkdtemp(join(tmpdir(),"xxpicore-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
 await updateProvider("namo-vpn",false,env,{root});await updateProvider(id,false,env,{root});assert.equal(await providerAllowed(id,env,{root}),false);
 await updateProvider(id,true,env,{root});assert.equal(await providerAllowed(id,env,{root}),true);assert.equal(await providerAllowed("namo-vpn",env,{root}),false);
});
test("XXPICore accepts only a complete matching worker catalog",async t=>{
 const old=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";t.after(()=>{if(old===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=old;});
 const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:id,structuredJson:doc,rawText:JSON.stringify(doc),isPartial:false,warnings:[],exporterCertified:false};
 const call=x=>fetchWorker("server-vpn",{providerId:id},{workerToken:"synthetic-worker-test"},{fetchImpl:async()=>Response.json(x)});
 assert.deepEqual((await (await call(good)).json()).structuredJson,doc);
 for(const bad of [{...good,isPartial:true},{...good,providerId:"xhypher-tunnel-pro"},{...good,rawText:"{}"},
   ...[{...doc,Servers:[]},{...doc,Networks:[7]},{...doc,Version:null}].map(d=>({...good,structuredJson:d,rawText:JSON.stringify(d)}))])
   await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
});
