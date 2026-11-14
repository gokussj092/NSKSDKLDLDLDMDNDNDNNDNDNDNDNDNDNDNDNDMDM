import test from "node:test";
import assert from "node:assert/strict";
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
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

function enabled(t){
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
}
test("Netcol denies private DNS before transport",async t=>{
 enabled(t);
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"raw.githubusercontent.com");return [{address:"127.0.0.1",family:4}];});
 t.mock.method(https,"request",()=>{throw Error("unexpected transport");});
 await assert.rejects(()=>downloadVpnCatalog("netcol-vpn"),{code:"REMOTE_NETWORK_DENIED"});
});
test("Netcol refuses same-origin and foreign redirects",async t=>{
 enabled(t);let location="https://raw.githubusercontent.com/jdavidag/update/main/Config";
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(url,options,callback)=>{
  assert.equal(url.href,"https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json");
  const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{const response=new EventEmitter();response.resume=()=>{};
   response.statusCode=302;response.headers={location};callback(response);});return req;
 });
 for(location of ["https://raw.githubusercontent.com/jdavidag/update/main/Config","https://attacker.invalid/"])
  await assert.rejects(()=>downloadVpnCatalog("netcol-vpn"),{code:"REMOTE_NETWORK_DENIED"});
});

test("Netcol launcher PNG, public format and card follow availability",()=>{
  const doc=catalog({availability:{"netcol-vpn":true}});
  assert(CATALOG_VERSION>=65, 'catalog version must not regress');assert(doc.apps.length>=61, 'catalog must retain existing apps');
  const card=doc.apps.find(x=>x.id==="netcol-vpn");
  assert.equal(card.name,"Netcol VPN");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"1cf1a5995d31294a39ffcc03630af88bfcee91577ba061852cc82eb7da9d0b39");
  assert.equal(iconFor("netcol-vpn").bytes.length,19306);
  assert(PUBLIC_PROVIDER_IDS.includes("netcol-vpn"));
  assert.equal(catalog({availability:{"netcol-vpn":false}}).apps.find(x=>x.id==="netcol-vpn").decodeEnabled,false);
  assert.equal(doc.formats.length,270);
  assert(!doc.formats.some(x=>x.suffix==="netcol"));
  assert(!JSON.stringify(card).includes("https://"));
});

test("Netcol persistent switch preserves existing provider states",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-netcol-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("speicers-pro-vpn",false,env,{root});
  const disabled=await updateProvider("netcol-vpn",false,env,{root});
  assert.equal(await providerAllowed("netcol-vpn",env,{root}),false);
  const enabled=await updateProvider("netcol-vpn",true,env,{root});
  assert(enabled.catalogVersion>disabled.catalogVersion);
  assert.equal(await providerAllowed("netcol-vpn",env,{root}),true);
  assert.equal(await providerAllowed("netcol-vpn",{...env,CLOUD_SERVER_VPN_ENABLED:"false"},{root}),false);
  const overview=await providerOverview(env,{root});
  assert.equal(overview.providers.find(x=>x.id==="netcol-vpn").name,"Netcol VPN");
  assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").enabled,false);
});

const document={Version:"synthetic",Servers:[{Name:"test",ServerPass:"synthetic-only"}],
  unknown:{preserve:[true,null,"é"]}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"netcol-vpn",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});

test("authenticated Netcol broker forwards all bytes and returns the complete worker document",async t=>{
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
    CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
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
  const bytes=Buffer.from("synthetic encrypted Netcol response");
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"raw.githubusercontent.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://raw.githubusercontent.com/jdavidag/setting/main/tO6oD1drTvL2.json");
    assert.equal(options.headers["User-Agent"],"Netcol VPN/14.2");
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=200;response.headers={};callback(response);
      response.emit("data",bytes);response.emit("end");
    });return req;
  });
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"netcol-vpn",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"netcol-vpn");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(workerResult());
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,document);assert.deepEqual(JSON.parse(result.rawText),document);
});

test("Netcol gateway rejects inconsistent or partial worker catalogs",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  for(const bad of [
    {...workerResult(),kind:"file"},{...workerResult(),providerId:"other"},
    {...workerResult(),rawText:"not JSON"},{...workerResult(),isPartial:true},
    {...workerResult(),rawText:JSON.stringify({...document,Servers:[]})},
    {...workerResult(),structuredJson:{...document,Servers:[1]},rawText:JSON.stringify({...document,Servers:[1]})},
  ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"netcol-vpn"},{workerToken:"w".repeat(48)},
    {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
