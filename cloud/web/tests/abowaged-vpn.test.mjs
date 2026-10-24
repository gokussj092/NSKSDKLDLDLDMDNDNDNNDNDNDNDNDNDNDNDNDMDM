import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import dns from "node:dns/promises";
import https from "node:https";
import {catalog,iconFor,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {downloadVpnCatalog,VpnProviderError} from "../lib/server-vpn-provider.mjs";
import {packPairedVpnCatalogs} from "../lib/paired-vpn-catalogs.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {providerPrerequisite,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {createHmac,randomUUID} from "node:crypto";
import {readFileSync} from "node:fs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";

test("AboWaged keeps its original 456508-byte icon and independent availability",()=>{
  assert(CATALOG_VERSION>=35);
  const app=catalog({availability:{"abowaged-vpn":true}}).apps.find(x=>x.id==="abowaged-vpn");
  assert.equal(app.name,"AboWaged VPN");assert.equal(app.decodeEnabled,true);
  assert.equal(app.iconSha256,"c54288a67e612f627d6fd00d553254d0f6f2184882a4c802dc263e9dc8eb1cf2");
  assert.equal(iconFor(app.id).bytes.length,456508);
  assert.equal(catalog({availability:{"abowaged-vpn":false}}).apps.find(x=>x.id===app.id).decodeEnabled,false);
  assert(PUBLIC_PROVIDER_IDS.includes(app.id));
  assert.equal(providerPrerequisite(app.id,{CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"}),true);
});

test("the secondary UDP picker has one pinned HTTPS source, never a caller URL",async t=>{
  const prior=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=prior;});
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"raw.githubusercontent.com");return [{address:"93.184.216.34",family:4}];
  });
  let calls=0;
  t.mock.method(https,"request",(url,options,callback)=>{
    calls++;assert.equal(url.href,"https://raw.githubusercontent.com/janatshaban/REMOTEUPDATER/refs/heads/main/pickerver");
    assert.equal(options.headers["User-Agent"],"AboWaged VPN/1.0");
    assert.equal(options.rejectUnauthorized,true);
    const request=new EventEmitter();request.destroy=()=>{};
    request.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};response.statusCode=200;response.headers={};
      callback(response);response.emit("data",Buffer.from("synthetic UDP data"));response.emit("end");
    });return request;
  });
  assert.equal((await downloadVpnCatalog("abowaged-vpn","udp")).toString(),"synthetic UDP data");
  await assert.rejects(()=>downloadVpnCatalog("abowaged-vpn","https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});
  assert.equal(calls,1);
});

test("both independent source bodies survive the paired transport without truncation",()=>{
  const sources={servers:Buffer.from("synthetic main bytes"),udp:Buffer.from("synthetic UDP bytes")};
  const bundle=JSON.parse(packPairedVpnCatalogs("abowaged-vpn",sources));
  assert.equal(bundle.kind,"spdecode-abowaged-vpn-catalogs-v1");
  assert.deepEqual(Object.keys(bundle.catalogs),["servers","udp"]);
  for(const [name,bytes] of Object.entries(sources))assert.deepEqual(Buffer.from(bundle.catalogs[name],"base64"),bytes);
  for(const invalid of [{servers:sources.servers},{...sources,users:Buffer.from("extra")},{...sources,udp:Buffer.alloc(0)}]){
    assert.throws(()=>packPairedVpnCatalogs("abowaged-vpn",invalid),VpnProviderError);
  }
});

test("gateway requires complete matching main and UDP JSON in the worker result",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  const document={provider:"abowaged-vpn",complete:true,catalogs:{
    servers:{Version:"1.0",Servers:[{Name:"synthetic",unknown:[null,false]}],Tweaks:[{Name:"synthetic"}]},
    udp:[{UDPserver:"example.invalid:443",obfs:"synthetic",auth:"synthetic",extra:""}],
  }};
  const result=doc=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"abowaged-vpn",
    structuredJson:doc,rawText:JSON.stringify(doc),isPartial:false,warnings:[],exporterCertified:false});
  const call=body=>fetchWorker("server-vpn",{providerId:"abowaged-vpn",dataBase64:"Zm9v"},
    {workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(body)});
  const response=await call(result(document));assert.equal(response.status,200);
  assert.deepEqual((await response.json()).structuredJson,document);
  for(const mutate of [d=>{delete d.catalogs.udp;},d=>{d.complete=false;},d=>{d.catalogs.udp=[];},
                       d=>{d.catalogs.servers.Servers=[null];},d=>{d.catalogs.udp[0].auth=null;}]){
    const invalid=structuredClone(document);mutate(invalid);
    await assert.rejects(()=>call(result(invalid)),/INVALID_WORKER_RESULT/);
  }
  const mismatch=result(document);mismatch.structuredJson=structuredClone(document);
  mismatch.structuredJson.catalogs.udp[0].extra="changed";
  await assert.rejects(()=>call(mismatch),/INVALID_WORKER_RESULT/);
});

for(const failUdp of [false,true])test(`authenticated AboWaged broker ${failUdp?"rejects a missing UDP source":"forwards both intact sources"}`,async t=>{
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
    CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
    CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
    CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
  for(const [key,value] of Object.entries(env)){
    const prior=process.env[key];process.env[key]=value;
    t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});
  }
  const fixture=JSON.parse(readFileSync(new URL("../../../tests/golden/abowaged_vectors.json",import.meta.url),"utf8"));
  const wire={servers:fixture.catalog.cipher,udp:fixture.udp.cipher};const seen=[];
  t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.hostname,"raw.githubusercontent.com");
    const source=url.pathname.endsWith("/Elk.txt")?"servers":"udp";seen.push(source);
    const request=new EventEmitter();request.destroy=()=>{};
    request.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=failUdp && source==="udp"?404:200;response.headers={};
      callback(response);
      if(response.statusCode===200){response.emit("data",Buffer.from(wire[source]));response.emit("end");}
    });return request;
  });
  const now=Math.floor(Date.now()/1000),jti=randomUUID();
  const signed=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
  const token=signed+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(signed).digest("base64url");
  const redis={get:async key=>key==="spc3:session:"+jti?"1":null,incr:async()=>1,
    expire:async()=>1,eval:async()=>1,zRem:async()=>1};
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"abowaged-vpn",consent:true}),
  });
  const report={provider:"abowaged-vpn",complete:true,catalogs:{servers:fixture.catalog.expected,udp:fixture.udp.expected}};
  let workerCalls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    workerCalls++;const input=JSON.parse(options.body);assert.equal(input.providerId,"abowaged-vpn");
    const bundle=JSON.parse(Buffer.from(input.dataBase64,"base64"));
    for(const name of ["servers","udp"])assert.equal(Buffer.from(bundle.catalogs[name],"base64").toString(),wire[name]);
    return Response.json({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"abowaged-vpn",
      structuredJson:report,rawText:JSON.stringify(report),isPartial:false,warnings:[],exporterCertified:false});
  }});
  assert.deepEqual(seen.sort(),["servers","udp"]);
  assert.equal(response.status,failUdp?502:200);assert.equal(workerCalls,failUdp?0:1);
  if(!failUdp)assert.deepEqual((await response.json()).structuredJson,report);
});
