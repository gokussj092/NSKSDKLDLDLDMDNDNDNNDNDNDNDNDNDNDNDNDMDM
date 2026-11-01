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

test("APNA original PNG, public format and card follow availability",()=>{
  const doc=catalog({availability:{"apna-vpn":true}});
  assert.equal(CATALOG_VERSION,59);assert.equal(doc.apps.length,53);
  const card=doc.apps.find(x=>x.id==="apna-vpn");
  assert.equal(card.name,"APNA VPN");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"01b38d6d006d24b6d50d3e32b3595bbdcd6bb0d634f2468ce3a009bd7cd966ee");
  assert.equal(iconFor("apna-vpn").bytes.length,21812);
  assert(PUBLIC_PROVIDER_IDS.includes("apna-vpn"));
  assert.equal(catalog({availability:{"apna-vpn":false}}).apps.find(x=>x.id==="apna-vpn").decodeEnabled,false);
  const format=doc.formats.find(x=>x.suffix==="apnavpn");
  assert.equal(format.cloudSupported,true);assert.equal(format.offlineSupported,false);
  assert.deepEqual(format.credentialFields,[]);
  assert(!JSON.stringify(card).includes("https://"));
});

test("APNA persistent switch preserves existing provider states",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-apna-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("speicers-pro-vpn",false,env,{root});
  const disabled=await updateProvider("apna-vpn",false,env,{root});
  assert.equal(await providerAllowed("apna-vpn",env,{root}),false);
  const enabled=await updateProvider("apna-vpn",true,env,{root});
  assert(enabled.catalogVersion>disabled.catalogVersion);
  assert.equal(await providerAllowed("apna-vpn",env,{root}),true);
  assert.equal(await providerAllowed("apna-vpn",{...env,CLOUD_SERVER_VPN_ENABLED:"false"},{root}),false);
  const overview=await providerOverview(env,{root});
  assert.equal(overview.providers.find(x=>x.id==="apna-vpn").name,"APNA VPN");
  assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").enabled,false);
});

const document={Version:"synthetic",Free_servers:[{name:"test",password:"synthetic-only"}],
  Payloads:[{payload:"GET / HTTP/1.1\r\n"}],Premium_servers:[],Vip_servers:[],Private_servers:[],
  unknown:{preserve:[true,null,"é"]}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"apna-vpn",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});

test("authenticated APNA broker forwards all bytes and returns the complete worker document",async t=>{
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
  const bytes=Buffer.from("synthetic encrypted APNA response");
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"paperonboard.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://paperonboard.com/updater/3c3c4c58d864ca394da16656b4d0c4");
    assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0");
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=200;response.headers={};callback(response);
      response.emit("data",bytes);response.emit("end");
    });return req;
  });
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"apna-vpn",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"apna-vpn");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(workerResult());
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,document);assert.deepEqual(JSON.parse(result.rawText),document);
});

test("APNA gateway rejects inconsistent or partial worker catalogs",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  for(const bad of [
    {...workerResult(),kind:"file"},{...workerResult(),providerId:"other"},
    {...workerResult(),rawText:"not JSON"},{...workerResult(),isPartial:true},
    {...workerResult(),rawText:JSON.stringify({...document,Payloads:[]})},
    {...workerResult(),structuredJson:{...document,Free_servers:[1]},rawText:JSON.stringify({...document,Free_servers:[1]})},
  ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"apna-vpn"},{workerToken:"w".repeat(48)},
    {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
