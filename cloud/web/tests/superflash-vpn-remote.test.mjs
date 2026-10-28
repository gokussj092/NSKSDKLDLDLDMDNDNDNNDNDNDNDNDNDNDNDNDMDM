import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {createHmac,randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {packPairedVpnCatalogs} from "../lib/paired-vpn-catalogs.mjs";
const packSuperFlashCatalogs=sources=>packPairedVpnCatalogs("superflash-vpn",sources);
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
const fixture=JSON.parse(readFileSync(new URL("../../../tests/golden/superflash_vpn_vectors.json",import.meta.url),"utf8"));
const endpoints={
 servers:["/apksdemons/apks2/refs/heads/main/supervpn/servr_superflash_sv5c",""],
 users:["/apksdemons/apks2/refs/heads/main/supervpn/user_superflash_sv5c",""],
};
const report={provider:"superflash-vpn",complete:true,catalogs:{servers:fixture.expectedServers,users:fixture.expectedUsers}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"superflash-vpn",
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
function transport(t,{failUsers=false,redirect=null,address="93.184.216.34"}={}){
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
   response.statusCode=redirect?302:failUsers&&source==="users"?503:200;
   response.headers=redirect?{location:redirect}:{};callback(response);
   if(response.statusCode===200){response.emit("data",Buffer.from(fixture[source],"base64"));response.emit("end");}
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
  method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},body:JSON.stringify({id:"superflash-vpn",consent:true}),
 })};
}
test("both fixed sources use vetted DNS, TLS and exact share paths without redirects",async t=>{
 environment(t);const seen=transport(t);
 for(const source of Object.keys(endpoints))assert.equal((await downloadVpnCatalog("superflash-vpn",source)).toString("base64"),fixture[source]);
 assert.deepEqual(seen,["servers","users"]);
 await assert.rejects(()=>downloadVpnCatalog("superflash-vpn","https://evil.invalid"),{code:"UNSUPPORTED_FORMAT"});
});
test("SuperFlash refuses even same-origin redirects from its validated direct sources",async t=>{
 environment(t);transport(t,{redirect:"https://raw.githubusercontent.com/other/file"});
 await assert.rejects(()=>downloadVpnCatalog("superflash-vpn","users"),{code:"REMOTE_NETWORK_DENIED"});
});
test("SuperFlash refuses private DNS before opening any HTTPS socket",async t=>{
 environment(t);const seen=transport(t,{address:"127.0.0.1"});
 await assert.rejects(()=>downloadVpnCatalog("superflash-vpn","servers"),{code:"REMOTE_NETWORK_DENIED"});assert.deepEqual(seen,[]);
});
test("two-source bundle retains all bytes and refuses omissions or overflow",()=>{
 const servers=Buffer.from("complete servers"),users=Buffer.from("complete users");
 const bundle=JSON.parse(packSuperFlashCatalogs({servers,users}));assert.equal(bundle.kind,"spdecode-superflash-vpn-catalogs-v1");
 for(const [name,data] of Object.entries({servers,users}))assert.equal(Buffer.from(bundle.catalogs[name],"base64").toString(),data.toString());
 assert.throws(()=>packSuperFlashCatalogs({servers}),{code:"REMOTE_RESPONSE_INVALID"});
 assert.throws(()=>packSuperFlashCatalogs({servers:Buffer.alloc(4*1024*1024),users:Buffer.alloc(4*1024*1024)}),{code:"REMOTE_TOO_LARGE"});
});
test("authenticated broker downloads both catalogs and sends an intact bundle to the worker",async t=>{
 const env=environment(t),seen=transport(t),{request,redis}=authenticatedRequest(env);let workerCalls=0;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
  workerCalls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
  const input=JSON.parse(options.body);assert.equal(input.providerId,"superflash-vpn");
  const bundle=JSON.parse(Buffer.from(input.dataBase64,"base64"));
  for(const source of ["servers","users"])assert.equal(Buffer.from(bundle.catalogs[source],"base64").toString("base64"),fixture[source]);
  return Response.json(workerResult());
 }});
 assert.equal(response.status,200);assert.equal(workerCalls,1);assert.deepEqual(seen.sort(),["servers","users"]);
 const result=await response.json();assert.equal(result.isPartial,false);assert.deepEqual(result.structuredJson,report);
});
test("one failed source cannot be reported as a complete successful catalog",async t=>{
 const env=environment(t);transport(t,{failUsers:true});const {request,redis}=authenticatedRequest(env);let workerCalled=false;
 const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async()=>{workerCalled=true;throw Error("unexpected");}});
 assert.equal(response.status,502);assert.equal(workerCalled,false);assert.equal((await response.json()).error.code,"REMOTE_PROVIDER_UNAVAILABLE");
});
test("worker result must contain matching complete server and user documents",async t=>{
 environment(t);
 for(const bad of [
  {...workerResult(),structuredJson:{...report,complete:false}},
  {...workerResult(),rawText:JSON.stringify({...report,catalogs:{servers:fixture.expectedServers}})},
  {...workerResult(),providerId:"other"},{...workerResult(),isPartial:true},
 ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"superflash-vpn"},{workerToken:"w".repeat(48)},
  {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});

