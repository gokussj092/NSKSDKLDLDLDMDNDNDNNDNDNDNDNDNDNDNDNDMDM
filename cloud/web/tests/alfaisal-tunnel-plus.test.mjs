import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {mkdtemp,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHmac,randomUUID} from "node:crypto";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {PUBLIC_PROVIDER_IDS,updateProvider,providerOverview,providerAllowed} from "../lib/c12-provider-controls.mjs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {downloadVpnCatalog,providerEnabled} from "../lib/server-vpn-provider.mjs";
import {alfaisalRequest,ALFAISAL_SOURCE,ALFAISAL_METADATA} from "../lib/alfaisal-protocol.mjs";
const V=JSON.parse(readFileSync(new URL("../../../tests/golden/alfaisal_vectors.json",import.meta.url)));
const R=V.request,ID="alfaisal-tunnel-plus";
const credentials={SPDECODE_ALFAISAL_API_KEY:R.apiKey,SPDECODE_ALFAISAL_SIGNING_KEY:R.signingKey,SPDECODE_ALFAISAL_DEVICE_UUID:R.deviceUuid};
function environment(t,extra={}){
 for(const [key,value] of Object.entries({CLOUD_SERVER_VPN_ENABLED:"true",...credentials,...extra})){
  const old=process.env[key];process.env[key]=value;
  t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});
 }
}
function transport(t,handler){
 const calls=[];
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"panel.alfaisalvpn.com");return [{address:"93.184.216.34",family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  const req=new EventEmitter();req.destroy=()=>{};
  req.end=body=>queueMicrotask(()=>{
   const call={url,options,body};calls.push(call);const reply=handler(call,calls.length);
   const res=new EventEmitter();res.resume=()=>{};res.statusCode=reply.status??200;res.headers=reply.headers??{};
   callback(res);if(res.statusCode===200){res.emit("data",reply.data??Buffer.from('{}'));res.emit("end");}
  });return req;
 });return calls;
}
const policy=Buffer.from('{"success":true,"json_requires_integrity":false}');
const workerResult=(document=V.expected)=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:ID,
 structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});

test("ALFAISAL signature matches independent JCA with the exact text key and serialized body",()=>{
 const result=alfaisalRequest(credentials,{timestamp:R.timestamp,nonce:R.nonce});
 assert.equal(result.body.toString(),R.body);assert.equal(result.headers["X-SIGNATURE"],R.signature);
 assert.equal(result.headers["X-API-KEY"],R.apiKey);
});
test("ALFAISAL requires all backend secrets before DNS and public card enablement",async t=>{
 environment(t);t.mock.method(dns,"lookup",()=>{throw Error("unexpected DNS");});
 for(const key of Object.keys(credentials)){
  const saved=process.env[key];process.env[key]="";
  assert.equal(providerEnabled(ID),false);
  assert.equal(catalog({availability:{[ID]:true}}).apps.find(x=>x.id===ID).decodeEnabled,false);
  await assert.rejects(()=>downloadVpnCatalog(ID),{code:"REMOTE_NOT_CONFIGURED"});process.env[key]=saved;
 }
 assert.equal(providerEnabled(ID,{...credentials,CLOUD_SERVER_VPN_ENABLED:"false"}),false);
});
test("ALFAISAL original icon, 55 cards and historical 254 formats remain available",t=>{
 environment(t);
 const doc=catalog({availability:{[ID]:true}}),card=doc.apps.find(x=>x.id===ID);
 assert.equal(CATALOG_VERSION,59);assert.equal(doc.apps.length,55);assert.equal(doc.formats.length,254);
 assert.equal(card.name,"ALFAISAL Tunnel+");assert.equal(card.decodeEnabled,true);
 assert.equal(card.iconSha256,"17c87ccc847a7babf655170044967e9120609793381800c664b73a17ad1ebaff");
 assert.equal(iconFor(ID).bytes.length,24520);assert(PUBLIC_PROVIDER_IDS.includes(ID));
 const publicText=JSON.stringify(doc);
 for(const secret of Object.values(credentials))assert(!publicText.includes(secret));
 assert(!JSON.stringify(card).includes("https://"));
});
test("ALFAISAL sends metadata GET followed by one correctly signed fixed POST",async t=>{
 environment(t);
 const encrypted=Buffer.from(V.catalog);
 const calls=transport(t,(call,n)=>{
  const {url,options,body}=call;
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  assert.equal(options.headers.Authorization,undefined);
  assert.equal(options.headers["Accept-Encoding"],"identity");assert.equal(options.headers["User-Agent"],"ALFAISAL Tunnel+/39");
  if(n===1){
   assert.equal(url.origin+url.pathname,ALFAISAL_METADATA);assert.equal(url.searchParams.get("device_uuid"),R.deviceUuid);
   assert.equal(url.searchParams.get("json_client_capability"),"2");assert.equal(options.method,"GET");assert.equal(body,undefined);
   assert.equal(options.headers["X-API-KEY"],undefined);assert.equal(options.headers["X-SIGNATURE"],undefined);
   return {data:policy};
  }
  assert.equal(url.href,ALFAISAL_SOURCE);assert.equal(options.method,"POST");assert.equal(body.toString(),R.body);
  assert.equal(options.headers["Content-Length"],String(body.length));assert.equal(options.headers["X-API-KEY"],R.apiKey);
  assert.match(options.headers["X-NONCE"],/^[0-9a-f]{32}$/);
  const expected=createHmac("sha256",R.signingKey).update(options.headers["X-TIMESTAMP"]+"."+options.headers["X-NONCE"]+".").update(body).digest("hex");
  assert.equal(options.headers["X-SIGNATURE"],expected);return {data:encrypted};
 });
 assert.deepEqual(await downloadVpnCatalog(ID),encrypted);assert.equal(calls.length,2);
 await assert.rejects(()=>downloadVpnCatalog(ID,"https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});assert.equal(calls.length,2);
});
test("ALFAISAL private DNS is rejected before any transport",async t=>{
 environment(t);t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
 t.mock.method(https,"request",()=>{throw Error("unexpected transport");});
 await assert.rejects(()=>downloadVpnCatalog(ID),{code:"REMOTE_NETWORK_DENIED"});
});
test("ALFAISAL does not fabricate integrity tokens or POST when metadata denies direct mode",async t=>{
 environment(t);let data;
 const calls=transport(t,()=>({data}));
 for(data of [Buffer.from('{"json_requires_integrity":true}'),Buffer.from('{"success":false,"json_requires_integrity":false}'),Buffer.from('{}')]){
  const n=calls.length;await assert.rejects(()=>downloadVpnCatalog(ID),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.equal(calls.length,n+1);
 }
});
test("ALFAISAL rejects every redirect without forwarding signed credentials",async t=>{
 environment(t);let location,post=false;
 const calls=transport(t,(call)=>call.options.method==="GET"&&post?{data:policy}:{status:302,headers:location===undefined?{}:{location}});
 for(post of [false,true])for(location of [undefined,ALFAISAL_SOURCE,"https://attacker.invalid/"]){
  const n=calls.length;await assert.rejects(()=>downloadVpnCatalog(ID),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls.length,n+(post?2:1));
 }
});
test("ALFAISAL never retries the signed POST nonce on upstream 503",async t=>{
 environment(t);const calls=transport(t,(_,n)=>n===1?{data:policy}:{status:503});
 await assert.rejects(()=>downloadVpnCatalog(ID),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.equal(calls.length,2);
});
test("ALFAISAL persistent switch preserves other providers and requires secrets",async t=>{
 const root=await mkdtemp(join(tmpdir(),"spdecode-alfaisal-"));t.after(()=>rm(root,{recursive:true,force:true}));
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",...credentials};
 await updateProvider("speicers-pro-vpn",false,env,{root});await updateProvider(ID,false,env,{root});
 assert.equal(await providerAllowed(ID,env,{root}),false);await updateProvider(ID,true,env,{root});
 assert.equal(await providerAllowed(ID,env,{root}),true);
 const overview=await providerOverview(env,{root});assert.equal(overview.providers.find(x=>x.id===ID).name,"ALFAISAL Tunnel+");
 assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").enabled,false);
 await assert.rejects(()=>updateProvider(ID,true,{...env,SPDECODE_ALFAISAL_DEVICE_UUID:""},{root}),/PROVIDER_NOT_CONFIGURED/);
});
test("ALFAISAL gateway requires complete three-list parity and accepts SSL-only networks",async t=>{
 environment(t,{WORKER_INTERNAL_URL:"http://decoder-worker:8787"});
 const doc=structuredClone(V.expected);doc.Networks=[];
 await fetchWorker("server-vpn",{providerId:ID},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(workerResult(doc))});
 for(const bad of [
  {...workerResult(),kind:"file"},{...workerResult(),providerId:"other"},{...workerResult(),isPartial:true},
  {...workerResult(),rawText:"bad"},{...workerResult(),rawText:JSON.stringify({...V.expected,SSLNetworks:[]})},
  workerResult({...V.expected,SSLNetworks:null}),workerResult({...V.expected,Networks:[],SSLNetworks:[]}),
 ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:ID},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});

test("authenticated ALFAISAL broker forwards all bytes and returns the complete worker document",async t=>{
  const env={...credentials,CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
    SPDECODE_VIP_SNIPHER_AUTHORIZATION:"Bearer synthetic-other-provider",CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
    CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
    CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
  for(const [key,value] of Object.entries(env)){
    const prior=process.env[key];process.env[key]=value;
    t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});
  }
  const now=Math.floor(Date.now()/1000),jti=randomUUID();
  const body=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
  const token=body+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(body).digest("base64url");
  const values=new Map([["spc3:session:"+jti,"1"]]);
  const redis={get:async key=>values.get(key)??null,
    incr:async key=>{const n=Number(values.get(key)||0)+1;values.set(key,String(n));return n;},
    expire:async()=>1,eval:async()=>1,zRem:async()=>1};
  const bytes=Buffer.from(V.catalog);
  const calls=transport(t,(call,n)=>n===1?{data:policy}:{data:bytes});
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"alfaisal-tunnel-plus",consent:true}),
  });
  let workerCalls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    workerCalls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"alfaisal-tunnel-plus");
    for(const value of Object.values(credentials))assert(!options.body.includes(value));
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(workerResult());
  }});
  assert.equal(response.status,200);assert.equal(calls.length,2);assert.equal(workerCalls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,V.expected);assert.deepEqual(JSON.parse(result.rawText),V.expected);
});

