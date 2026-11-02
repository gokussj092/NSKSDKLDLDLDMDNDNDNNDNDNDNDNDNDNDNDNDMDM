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
test("IZPH denies private DNS before transport",async t=>{
 enabled(t);
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"raw.githubusercontent.com");return [{address:"127.0.0.1",family:4}];});
 t.mock.method(https,"request",()=>{throw Error("unexpected transport");});
 await assert.rejects(()=>downloadVpnCatalog("izph-vpn-pro"),{code:"REMOTE_NETWORK_DENIED"});
});
test("IZPH refuses same-origin and foreign redirects",async t=>{
 enabled(t);let location="https://raw.githubusercontent.com/jdavidag/update/main/Config";
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(url,options,callback)=>{
  assert.equal(url.href,"https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49");
  const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{const response=new EventEmitter();response.resume=()=>{};
   response.statusCode=302;response.headers={location};callback(response);});return req;
 });
 for(location of ["https://raw.githubusercontent.com/jdavidag/update/main/Config","https://attacker.invalid/"])
  await assert.rejects(()=>downloadVpnCatalog("izph-vpn-pro"),{code:"REMOTE_NETWORK_DENIED"});
});

test("IZPH launcher PNG, public format and card follow availability",()=>{
  const doc=catalog({availability:{"izph-vpn-pro":true}});
  assert.equal(CATALOG_VERSION,60);assert.equal(doc.apps.length,58);
  const card=doc.apps.find(x=>x.id==="izph-vpn-pro");
  assert.equal(card.name,"IZPH VPN PRO");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"66ba9cb37ebf9c2ec8ea71bff78be16b886c794b2c13c9f6d40d9c36bb1442cb");
  assert.equal(iconFor("izph-vpn-pro").bytes.length,156041);
  assert(PUBLIC_PROVIDER_IDS.includes("izph-vpn-pro"));
  assert.equal(catalog({availability:{"izph-vpn-pro":false}}).apps.find(x=>x.id==="izph-vpn-pro").decodeEnabled,false);
  assert.equal(doc.formats.length,255);
  assert(doc.formats.some(x=>x.suffix==="izph"));
  assert(!JSON.stringify(card).includes("https://"));
});

test("IZPH persistent switch preserves existing provider states",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-netcol-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("speicers-pro-vpn",false,env,{root});
  const disabled=await updateProvider("izph-vpn-pro",false,env,{root});
  assert.equal(await providerAllowed("izph-vpn-pro",env,{root}),false);
  const enabled=await updateProvider("izph-vpn-pro",true,env,{root});
  assert(enabled.catalogVersion>disabled.catalogVersion);
  assert.equal(await providerAllowed("izph-vpn-pro",env,{root}),true);
  assert.equal(await providerAllowed("izph-vpn-pro",{...env,CLOUD_SERVER_VPN_ENABLED:"false"},{root}),false);
  const overview=await providerOverview(env,{root});
  assert.equal(overview.providers.find(x=>x.id==="izph-vpn-pro").name,"IZPH VPN PRO");
  assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").enabled,false);
});

const document={Version:"synthetic",Servers:[{Name:"test",ServerPass:"synthetic-only"}],
  Networks:[{Name:"test-network",Payload:"synthetic-only"}],unknown:{preserve:[true,null,"é"]}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"izph-vpn-pro",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});

test("authenticated IZPH broker forwards all bytes and returns the complete worker document",async t=>{
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
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
  const bytes=Buffer.from("synthetic encrypted IZPH response");
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"raw.githubusercontent.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/izph49");
    assert.equal(options.headers["User-Agent"],"IZPH VPN PRO/6.0");
    assert.equal(options.headers.Authorization,undefined);
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=200;response.headers={};callback(response);
      response.emit("data",bytes);response.emit("end");
    });return req;
  });
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"izph-vpn-pro",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"izph-vpn-pro");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(workerResult());
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,document);assert.deepEqual(JSON.parse(result.rawText),document);
});

test("IZPH gateway rejects inconsistent or partial worker catalogs",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  for(const bad of [
    {...workerResult(),kind:"file"},{...workerResult(),providerId:"other"},
    {...workerResult(),rawText:"not JSON"},{...workerResult(),isPartial:true},
    {...workerResult(),rawText:JSON.stringify({...document,Servers:[]})},
    {...workerResult(),structuredJson:{...document,Servers:[1]},rawText:JSON.stringify({...document,Servers:[1]})},
  ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"izph-vpn-pro"},{workerToken:"w".repeat(48)},
    {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
