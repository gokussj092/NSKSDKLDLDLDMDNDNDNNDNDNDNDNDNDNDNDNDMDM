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

test("BD NET original PNG, public format and card follow availability",()=>{
  const doc=catalog({availability:{"bd-net-vpn":true}});
  assert.equal(CATALOG_VERSION,53);assert.equal(doc.apps.length,48);
  const card=doc.apps.find(x=>x.id==="bd-net-vpn");
  assert.equal(card.name,"BD NET VPN");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"46c3149a1e70087a9c34bc4b06b432ebd285b64762ab23ed4368d2cb4b7bce45");
  assert.equal(iconFor("bd-net-vpn").bytes.length,36294);
  assert(PUBLIC_PROVIDER_IDS.includes("bd-net-vpn"));
  assert.equal(catalog({availability:{"bd-net-vpn":false}}).apps.find(x=>x.id==="bd-net-vpn").decodeEnabled,false);
  const format=doc.formats.find(x=>x.suffix==="bdnet");
  assert.equal(format.cloudSupported,true);assert.equal(format.offlineSupported,true);
  assert.deepEqual(format.credentialFields,[]);
  assert(!JSON.stringify(card).includes("https://"));
});

test("BD NET persistent switch preserves existing provider states",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-bd-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("speicers-pro-vpn",false,env,{root});
  const disabled=await updateProvider("bd-net-vpn",false,env,{root});
  assert.equal(await providerAllowed("bd-net-vpn",env,{root}),false);
  const enabled=await updateProvider("bd-net-vpn",true,env,{root});
  assert(enabled.catalogVersion>disabled.catalogVersion);
  assert.equal(await providerAllowed("bd-net-vpn",env,{root}),true);
  assert.equal(await providerAllowed("bd-net-vpn",{...env,CLOUD_SERVER_VPN_ENABLED:"false"},{root}),false);
  const overview=await providerOverview(env,{root});
  assert.equal(overview.providers.find(x=>x.id==="bd-net-vpn").name,"BD NET VPN");
  assert.equal(overview.providers.find(x=>x.id==="speicers-pro-vpn").enabled,false);
});

const document={Version:"synthetic",Free_servers:[{name:"test",password:"synthetic-only"}],
  Payloads:[{payload:"GET / HTTP/1.1\r\n"}],Premium_servers:[],Vip_servers:[],Private_servers:[],
  unknown:{preserve:[true,null,"é"]}};
const workerResult=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"bd-net-vpn",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});

test("authenticated BD NET broker forwards all bytes and returns the complete worker document",async t=>{
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
  const bytes=Buffer.from("synthetic encrypted BD NET response");
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"raw.githubusercontent.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://raw.githubusercontent.com/panigbatanc/BDNET2023/main/JSONDEC2025");
    assert.equal(options.headers["User-Agent"],"BD NET VPN/PrinceBuild111");
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=200;response.headers={};callback(response);
      response.emit("data",bytes);response.emit("end");
    });return req;
  });
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"bd-net-vpn",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"bd-net-vpn");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(workerResult());
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,document);assert.deepEqual(JSON.parse(result.rawText),document);
});

test("BD NET gateway rejects inconsistent or partial worker catalogs",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;
  process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  for(const bad of [
    {...workerResult(),kind:"file"},{...workerResult(),providerId:"other"},
    {...workerResult(),rawText:"not JSON"},{...workerResult(),isPartial:true},
    {...workerResult(),rawText:JSON.stringify({...document,Payloads:[]})},
    {...workerResult(),structuredJson:{...document,Free_servers:[1]},rawText:JSON.stringify({...document,Free_servers:[1]})},
  ])await assert.rejects(()=>fetchWorker("server-vpn",{providerId:"bd-net-vpn"},{workerToken:"w".repeat(48)},
    {fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});
