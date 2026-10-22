import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHmac,randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {packPairedVpnCatalogs} from "../lib/paired-vpn-catalogs.mjs";
const packV2plusCatalogs=sources=>packPairedVpnCatalogs("v2ray-tunnel-plus",sources);
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const fixture=JSON.parse(readFileSync(new URL("../../../tests/golden/v2ray_tunnel_plus_vectors.json",import.meta.url),"utf8"));
const endpoints={
 base64:["/roosterkid/openproxylist/main/V2RAY_BASE64.txt",""],
 raw:["/roosterkid/openproxylist/main/V2RAY_RAW.txt",""],
};
const report={provider:"v2ray-tunnel-plus",complete:true,catalogs:{base64:fixture.expectedBase64,raw:fixture.expectedRaw}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"v2ray-tunnel-plus",
 structuredJson:report,rawText:JSON.stringify(report),isPartial:false,warnings:[],exporterCertified:false});
function environment(t){
 const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
  CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
  CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
  CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
 for(const [key,value] of Object.entries(env)){
  const prior=process.env[key];process.env[key]=value;
  t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});
 }return env;
}
function transport(t,{failRaw=false,redirect=null,address="93.184.216.34"}={}){
 const seen=[];
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"raw.githubusercontent.com");return [{address,family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  const source=Object.keys(endpoints).find(name=>url.pathname===endpoints[name][0]);
  assert(source);seen.push(source);
  assert.equal(url.hostname,"raw.githubusercontent.com");assert.equal(url.search,endpoints[source][1]);
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  options.lookup(url.hostname,{},(err,ip,family)=>{assert.equal(err,null);assert.equal(ip,address);assert.equal(family,4);});
  const request=new EventEmitter();request.destroy=()=>{};
  request.end=()=>queueMicrotask(()=>{
   const response=new EventEmitter();response.resume=()=>{};
   response.statusCode=redirect?302:failRaw&&source==="raw"?503:200;
   response.headers=redirect?{location:redirect}:{};callback(response);
   if(response.statusCode===200){response.emit("data",Buffer.from(source==="raw"?fixture.raw:fixture.base64));response.emit("end");}
  });return request;
 });return seen;
}
class Redis {
 constructor(jti){this.values=new Map([["spc3:session:"+jti,"1"]]);}
 async get(key){return this.values.get(key)??null;}
 async incr(key){const next=Number(this.values.get(key)||0)+1;this.values.set(key,String(next));return next;}
 async expire(){return 1;} async eval(){return 1;} async zRem(){return 1;}
}
function authenticatedRequest(env){
 const now=Math.floor(Date.now()/1000),jti=randomUUID();
 const body=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
 const token=body+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(body).digest("base64url");
 return {redis:new Redis(jti),request:new Request("https://api.example.test/api/v1/server-vpn/decode",{
  method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},body:JSON.stringify({id:"v2ray-tunnel-plus",consent:true}),
 })};
}
test("both fixed sources use vetted DNS, TLS and exact share paths without redirects",async t=>{
 environment(t);const seen=transport(t);
 for(const source of Object.keys(endpoints))assert.equal((await downloadVpnCatalog("v2ray-tunnel-plus",source)).toString(),source==="raw"?fixture.raw:fixture.base64);
 assert.deepEqual(seen,["base64","raw"]);
 await assert.rejects(()=>downloadVpnCatalog("v2ray-tunnel-plus","https://evil.invalid"),{code:"UNSUPPORTED_FORMAT"});
});
test("V2plus refuses even same-origin redirects from its validated direct sources",async t=>{
 environment(t);transport(t,{redirect:"https://raw.githubusercontent.com/other/file"});
 await assert.rejects(()=>downloadVpnCatalog("v2ray-tunnel-plus","raw"),{code:"REMOTE_NETWORK_DENIED"});
});
test("V2plus refuses private DNS before opening any HTTPS socket",async t=>{
 environment(t);const seen=transport(t,{address:"127.0.0.1"});
 await assert.rejects(()=>downloadVpnCatalog("v2ray-tunnel-plus","base64"),{code:"REMOTE_NETWORK_DENIED"});assert.deepEqual(seen,[]);
});
test("two-source bundle retains all bytes and refuses omissions or overflow",()=>{
 const base64=Buffer.from("complete base64"),raw=Buffer.from("complete raw");
 const bundle=JSON.parse(packV2plusCatalogs({base64,raw}));assert.equal(bundle.kind,"spdecode-v2ray-tunnel-plus-catalogs-v1");
 for(const [name,data] of Object.entries({base64,raw}))assert.equal(Buffer.from(bundle.catalogs[name],"base64").toString(),data.toString());
 assert.throws(()=>packV2plusCatalogs({base64}),{code:"REMOTE_RESPONSE_INVALID"});
 assert.throws(()=>packV2plusCatalogs({base64:Buffer.alloc(4*1024*1024),raw:Buffer.alloc(4*1024*1024)}),{code:"REMOTE_TOO_LARGE"});
});
test("authenticated broker downloads both catalogs and sends an intact bundle to the worker",async t=>{
 const env=environment(t),seen=transport(t),{request,redis}=authenticatedRequest(env);let workerCalls=0;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
  workerCalls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
  const input=JSON.parse(options.body);assert.equal(input.providerId,"v2ray-tunnel-plus");
  const bundle=JSON.parse(Buffer.from(input.dataBase64,"base64"));
  for(const source of ["base64","raw"])assert.equal(Buffer.from(bundle.catalogs[source],"base64").toString(),source==="raw"?fixture.raw:fixture.base64);
  return Response.json(workerResult());
 }});
 assert.equal(response.status,200);assert.equal(workerCalls,1);assert.deepEqual(seen.sort(),["base64","raw"]);
 const result=await response.json();assert.equal(result.isPartial,false);assert.deepEqual(result.structuredJson,report);
});
test("one failed source cannot be reported as a complete successful catalog",async t=>{
 const env=environment(t);transport(t,{failRaw:true});const {request,redis}=authenticatedRequest(env);let workerCalled=false;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async()=>{workerCalled=true;throw Error("unexpected");}});
 assert.equal(response.status,502);assert.equal(workerCalled,false);assert.equal((await response.json()).error.code,"REMOTE_PROVIDER_UNAVAILABLE");
});
test("worker result must contain matching complete subscription documents",async t=>{
 environment(t);
 for(const bad of [
  {...workerResult(),structuredJson:{...report,complete:false}},
  {...workerResult(),rawText:JSON.stringify({...report,catalogs:{base64:fixture.expectedBase64}})},
  {...workerResult(),providerId:"other"},{...workerResult(),isPartial:true},
 ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"v2ray-tunnel-plus"},{workerToken:"w".repeat(48)},
  {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});

test("paired catalog framing rejects unknown provider identities",()=>{
 assert.throws(()=>packPairedVpnCatalogs("https://evil.invalid",{base64:Buffer.from("a"),raw:Buffer.from("b")}),{code:"UNSUPPORTED_FORMAT"});
});
