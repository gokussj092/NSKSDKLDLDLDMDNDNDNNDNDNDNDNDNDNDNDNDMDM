import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import http from "node:http";
import {EventEmitter} from "node:events";
import {readFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {SUPPLIED_INTEGRATIONS,SUPPLIED_CATALOG_ITEMS,suppliedRequests} from "../lib/supplied-integrations.mjs";
import {catalog,iconFor} from "../lib/server-vpn-catalog.mjs";
import {providerIds,providerEnabled,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {loadServerVpnResult} from "../lib/server-vpn-gateway.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {catalogDefaultEnabled} from "../lib/catalog-provider-policy.mjs";
import {DEFAULT_DTUNNEL_REQUEST_ID} from "../lib/dtunnel-credentials.server.mjs";

function environment(t,extra={}){
 for(const [key,value] of Object.entries({CLOUD_SERVER_VPN_ENABLED:"true",...extra})){
  const old=process.env[key];process.env[key]=value;
  t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});
 }
}
function network(t,answer=()=>({body:Buffer.from("synthetic encrypted response")})){
 const calls=[];t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 const request=(url,options,callback)=>{
  const call={url,options};calls.push(call);const req=new EventEmitter();req.destroy=()=>{};
  req.end=body=>{call.body=body;queueMicrotask(()=>{
   const a=answer(url,options),res=new EventEmitter();res.statusCode=a.status??200;res.headers=a.headers??{};res.resume=()=>{};
   callback(res);if(res.statusCode===200){res.emit("data",a.body);res.emit("end");}
  });};return req;
 };
 t.mock.method(https,"request",request);t.mock.method(http,"request",request);return calls;
}
test("all supplied catalog methods reach pinned fixed sources and operator controls",async t=>{
 environment(t,{SPDECODE_DTUNNEL_REQUEST_ID:"synthetic-authorized-account"});const calls=network(t);
 assert.equal(SUPPLIED_INTEGRATIONS.length,57);
 for(const item of SUPPLIED_CATALOG_ITEMS){
  assert(PUBLIC_PROVIDER_IDS.includes(item.id));
  const card=catalog().apps.find(x=>x.id===item.id);assert(card);assert(iconFor(item.id).bytes.length);
  assert.equal(card.decodeEnabled,Boolean(item.remote)&&catalogDefaultEnabled(item.id));
  if(!item.remote){assert(!providerIds().includes(item.id));continue;}
  assert(providerIds().includes(item.id));
  if(item.id==="catnet-vpn")continue; // Dedicated preflight protocol has its own regressions.
  const before=calls.length,result=await downloadVpnCatalog(item.id);
  assert(result.length);assert(calls.length>before);
  assert(calls.slice(before).every(x=>x.options.lookup));
 }
 const requestFor=id=>calls.find(x=>x.url.href===suppliedRequests(id)[0].url);
 assert.equal(requestFor("at-net-vpn").body.toString(),"hash=xsandokBCUpdatex");
 assert.equal(requestFor("shield-tunnel").body.toString(),"hash=xsandokUpdatex");
 assert.equal(requestFor("dtunnel-mod").options.headers["dtunnel-token"],"synthetic-authorized-account");
 assert(!JSON.stringify(catalog()).includes("synthetic-authorized-account"));
 assert(!JSON.stringify(catalog()).includes("catalogModule"));
});
test("DTunnel uses the authorized script default; invalid explicit IDs never trigger downloads",async t=>{
 environment(t,{SPDECODE_DTUNNEL_REQUEST_ID:""});const calls=network(t);
 assert(providerIds().includes("dtunnel-mod"));assert.equal(providerEnabled("dtunnel-mod"),true);
 assert(catalog().apps.find(x=>x.id==="dtunnel-mod").decodeEnabled);
 await downloadVpnCatalog("dtunnel-mod");
 assert(calls[0].options.headers["dtunnel-token"]===DEFAULT_DTUNNEL_REQUEST_ID);
 assert(!JSON.stringify(catalog()).includes(DEFAULT_DTUNNEL_REQUEST_ID));
 assert(!JSON.stringify(SUPPLIED_INTEGRATIONS).includes(DEFAULT_DTUNNEL_REQUEST_ID));
 const before=calls.length;
 for(const value of ["bad\r\nInjected: yes","x".repeat(513)]){
  process.env.SPDECODE_DTUNNEL_REQUEST_ID=value;assert.equal(providerEnabled("dtunnel-mod"),false);
  await assert.rejects(()=>downloadVpnCatalog("dtunnel-mod"),{code:"REMOTE_NOT_CONFIGURED"});
 }
 await assert.rejects(()=>downloadVpnCatalog("at-net-vpn","https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});
 assert.equal(calls.length,before);
});
test("supplied routes reject private DNS, redirects, HTML and truncated empty replies",async t=>{
 environment(t);
 const calls=network(t,()=>({status:302,headers:{location:"https://attacker.invalid/"}}));
 await assert.rejects(()=>downloadVpnCatalog("rev-hunter"),{code:"REMOTE_NETWORK_DENIED"});
 assert.equal(calls.length,1);
 t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
 await assert.rejects(()=>downloadVpnCatalog("rev-hunter"),{code:"REMOTE_NETWORK_DENIED"});
 assert.equal(calls.length,1);
});
test("DTunnel broker to real isolated worker preserves every stored profile",async t=>{
 environment(t,{SPDECODE_DTUNNEL_REQUEST_ID:"synthetic-account",WORKER_INTERNAL_URL:"http://decoder-worker:8787"});
 const raw=readFileSync(new URL("../../../decoders/Python/apps/DTunnel_Mod/catalog_sample.b64",import.meta.url));
 const expected=JSON.parse(readFileSync(new URL("../../../decoders/Python/apps/DTunnel_Mod/catalog_sample.json",import.meta.url)));
 network(t,()=>({body:raw}));
 const response=await loadServerVpnResult("dtunnel-mod",{fetchImpl:async(url,options)=>{
  const script="import sys,json,base64;from cloud.workers.python.engine import decode_provider_catalog;r=json.load(sys.stdin);print(json.dumps(decode_provider_catalog(r['providerId'],base64.b64decode(r['dataBase64']))))";
  const p=spawnSync(process.env.SPC_QA_PYTHON||"python3",["-c",script],{cwd:new URL("../../../",import.meta.url),input:options.body,encoding:"utf8",timeout:15000,maxBuffer:4*1024*1024});
  assert.equal(p.status,0,"isolated catalog worker must succeed");return new Response(p.stdout,{status:200});
 }});
 assert.equal(response.status,200);const result=await response.json();
 const digest=x=>createHash("sha256").update(JSON.stringify(x)).digest("hex");
 assert.equal(digest(result.structuredJson),digest(expected));assert.equal(result.structuredJson.length,49);
});
test("new worker results cannot substitute a provider, truncate JSON or hide partial output",async t=>{
 environment(t,{WORKER_INTERNAL_URL:"http://decoder-worker:8787"});
 const id="pukang-vpn",doc={Servers:[{name:"synthetic"}],Networks:[]};
 const good={status:"success",kind:"vpn_catalog",providerId:id,rawText:JSON.stringify(doc),structuredJson:doc,isPartial:false};
 const call=value=>fetchWorker("server-vpn",{providerId:id},{workerToken:"synthetic"},{fetchImpl:async()=>Response.json(value)});
 assert.equal((await call(good)).status,200);
 for(const bad of [{...good,providerId:"dtunnel-mod"},{...good,rawText:"{}"},{...good,isPartial:true}])
  await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
});
