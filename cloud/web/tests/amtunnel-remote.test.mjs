import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHmac,randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const fixture=JSON.parse(readFileSync(new URL("../../../tests/golden/amtunnel_catalog_vectors.json",import.meta.url),"utf8"));
const ANDROID_UA="Mozilla/5.0 (Linux; Android 14; Redmi 14C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36";
const endpoints={
 servers:["/updater/8112011e98856d3ca814d0f8ce3231",""],
};
const report=fixture.expected;
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"am-tunnel-lite",
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
// The live server cuts every response to multiples of 16 KiB, so the broker
// fetches by ranges. The mock answers each Range request with the exact
// slice (206 + Content-Range), like LiteSpeed does.
function transport(t,{failUsers=false,redirect=null,address="93.184.216.34",abortFirst=false}={}){
 const seen=[];
 let calls=0;
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"freedomnavigate.com");return [{address,family:4}];});
 t.mock.method(https,"request",(url,options,callback)=>{
  const source=Object.keys(endpoints).find(name=>url.pathname===endpoints[name][0]);
  assert(source);seen.push(source);
  assert.equal(url.hostname,"freedomnavigate.com");assert.equal(url.search,endpoints[source][1]);
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  assert.equal(options.headers["User-Agent"],ANDROID_UA);
  options.lookup(url.hostname,{},(err,ip,family)=>{assert.equal(err,null);assert.equal(ip,address);assert.equal(family,4);});
  const request=new EventEmitter();request.destroy=()=>{};
  request.end=()=>queueMicrotask(()=>{
   calls++;
   const response=new EventEmitter();response.resume=()=>{};
   const range=String(options.headers.Range||"");
   const match=/^bytes=(\d+)-(\d+)$/.exec(range);
   assert(match,"Range header missing: "+range);
   const start=Number(match[1]),end=Math.min(Number(match[2]),fixture.catalog.length-1);
   const slice=Buffer.from(fixture.catalog.slice(start,end+1));
   response.statusCode=redirect?302:failUsers?503:206;
   response.headers=redirect?{location:redirect}:{ "content-range":`bytes ${start}-${end}/${fixture.catalog.length}`,"content-length":String(slice.length)};
   if(abortFirst&&calls===1){
    // First range aborts mid-response, like the live server does; the
    // broker must retry the same range instead of failing or truncating.
    // (206 headers are already set: the real server aborts after them.)
    callback(response);response.emit("aborted");return;
   }
   callback(response);
   if(response.statusCode===206){response.emit("data",slice);response.emit("end");}
  });return request;
 });return seen;
}
class Redis {
 constructor(jti){this.values=new Map([["spc3:session:"+jti,"1"]]);}
 async get(key){return this.values.get(key)??null;}
 async incr(key){const next=Number(this.values.get(key)||0)+1;this.values.set(key,String(next));return next;}
 async expire(){return 1;} async eval(script,opts){if(script.includes("spdecode:throttle:v1"))return this.incr(opts.keys[0]);return 1;} async zRem(){return 1;}
}
function authenticatedRequest(env){
 const now=Math.floor(Date.now()/1000),jti=randomUUID();
 const body=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
 const token=body+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(body).digest("base64url");
 return {redis:new Redis(jti),request:new Request("https://api.example.test/api/v1/server-vpn/decode",{
  method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},body:JSON.stringify({id:"am-tunnel-lite",consent:true}),
 })};
}
test("fixed source uses vetted DNS, TLS, the Android UA and ranged 206 downloads",async t=>{
 environment(t);const seen=transport(t);
 for(const source of Object.keys(endpoints))assert.equal((await downloadVpnCatalog("am-tunnel-lite",source)).toString(),fixture.catalog);
 assert.deepEqual(seen,["servers"]);
 await assert.rejects(()=>downloadVpnCatalog("am-tunnel-lite","https://evil.invalid"),{code:"UNSUPPORTED_FORMAT"});
});
test("AM Tunnel Lite retries an aborted range instead of truncating the catalog",async t=>{
 environment(t);transport(t,{abortFirst:true});
 assert.equal((await downloadVpnCatalog("am-tunnel-lite","servers")).toString(),fixture.catalog);
});
test("AM Tunnel Lite refuses even same-origin redirects from its validated direct source",async t=>{
 environment(t);transport(t,{redirect:"https://freedomnavigate.com/other/file"});
 await assert.rejects(()=>downloadVpnCatalog("am-tunnel-lite","servers"),{code:"REMOTE_NETWORK_DENIED"});
});
test("AM Tunnel Lite refuses private DNS before opening any HTTPS socket",async t=>{
 environment(t);const seen=transport(t,{address:"127.0.0.1"});
 await assert.rejects(()=>downloadVpnCatalog("am-tunnel-lite","servers"),{code:"REMOTE_NETWORK_DENIED"});assert.deepEqual(seen,[]);
});
test("authenticated broker sends the entire single-source catalog to the worker",async t=>{
 const env=environment(t),seen=transport(t),{request,redis}=authenticatedRequest(env);let workerCalls=0;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
  workerCalls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
  const input=JSON.parse(options.body);assert.equal(input.providerId,"am-tunnel-lite");
  assert.equal(Buffer.from(input.dataBase64,"base64").toString(),fixture.catalog);
  return Response.json(workerResult());
 }});
 assert.equal(response.status,200);assert.equal(workerCalls,1);assert.deepEqual(seen,["servers"]);
 const result=await response.json();assert.equal(result.isPartial,false);assert.deepEqual(result.structuredJson,report);
});
test("unavailable source cannot be reported as a successful catalog",async t=>{
 const env=environment(t);transport(t,{failUsers:true});const {request,redis}=authenticatedRequest(env);let workerCalled=false;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async()=>{workerCalled=true;throw Error("unexpected");}});
 assert.equal(response.status,502);assert.equal(workerCalled,false);assert.equal((await response.json()).error.code,"REMOTE_PROVIDER_UNAVAILABLE");
});
test("worker result must match complete free-server and payload documents",async t=>{
 environment(t);
 for(const bad of [
  {...workerResult(),kind:"file"},
  {...workerResult(),rawText:JSON.stringify({...report,Free_servers:[]})},
  {...workerResult(),rawText:JSON.stringify({...report,Payloads:[]})},
  {...workerResult(),providerId:"other"},{...workerResult(),isPartial:true},
 ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"am-tunnel-lite"},{workerToken:"w".repeat(48)},
  {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
