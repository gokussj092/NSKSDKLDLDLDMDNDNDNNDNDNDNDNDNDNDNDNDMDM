import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import dns from "node:dns/promises";
import {EventEmitter} from "node:events";
import {mkdtemp,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {createHmac,randomUUID} from "node:crypto";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {providerEnabled,providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS,updateProvider,providerOverview,providerAllowed} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {POST as icon} from "../app/api/v1/server-vpn/icon/route.js";

const secret="Bearer synthetic-vip-test-credential";
const source="https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main";
function enabled(t){
  for(const [key,value] of Object.entries({CLOUD_SERVER_VPN_ENABLED:"true",SPDECODE_VIP_SNIPHER_AUTHORIZATION:secret})){
    const old=process.env[key];process.env[key]=value;
    t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});
  }
}
test("VIP Snipher original icon and download follow secret configuration and availability",t=>{
  enabled(t);
  const doc=catalog({availability:{"vip-snipher-pro":true}});
  assert.equal(CATALOG_VERSION,72);assert.equal(doc.apps.length,66);
  const card=doc.apps.find(x=>x.id==="vip-snipher-pro");
  assert.equal(card.name,"VIP Snipher Pro");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"6a2ecaacc5fdf2a20f23cf31a58838854d7573dfb58c738274e150c31978e1e6");
  assert.equal(iconFor(card.id).bytes.length,25374);
  assert(!JSON.stringify(card).includes("https://"));
  assert.equal(doc.formats.length,256);
  assert(!doc.formats.some(x=>x.suffix==="js"||x.suffix==="rj"));
  assert.equal(catalog({availability:{"vip-snipher-pro":false}}).apps.find(x=>x.id===card.id).decodeEnabled,false);
  delete process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION;
  assert.equal(catalog({availability:{"vip-snipher-pro":true}}).apps.find(x=>x.id===card.id).decodeEnabled,false);
  assert(!JSON.stringify(doc).includes(secret));
});

test("VIP requires a configured authorization before DNS or transport",async t=>{
  enabled(t);
  t.mock.method(dns,"lookup",()=>{throw Error("unexpected DNS");});
  t.mock.method(https,"request",()=>{throw Error("unexpected provider transport");});
  assert(providerIds().includes("vip-snipher-pro"));
  assert(PUBLIC_PROVIDER_IDS.includes("vip-snipher-pro"));
  assert.equal(providerEnabled("vip-snipher-pro",{CLOUD_SERVER_VPN_ENABLED:"true",SPDECODE_VIP_SNIPHER_AUTHORIZATION:secret}),true);
  assert.equal(providerEnabled("vip-snipher-pro",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
  for(const value of ["", "Bearer ", "Basic private-sentinel", "Bearer bad\r\nX-Test: injected", "Bearer bad\n", "Bearer "+"x".repeat(2048)]){
    process.env.SPDECODE_VIP_SNIPHER_AUTHORIZATION=value;
    await assert.rejects(()=>downloadVpnCatalog("vip-snipher-pro"),{code:"REMOTE_NOT_CONFIGURED"});
  }
  assert(!catalog().apps.some(x=>x.id==="90net-vpn"));
});

test("VIP original icon is downloadable through the existing metadata API",async()=>{
  const response=await icon(new Request("https://api.example.test/api/v1/server-vpn/icon",{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({id:"vip-snipher-pro"}),
  }));
  assert.equal(response.status,200);
  const result=await response.json();
  assert.deepEqual(Buffer.from(result.contentBase64,"base64"),iconFor("vip-snipher-pro").bytes);
});

const document={Version:"synthetic-29",Servers:[{Name:"test",unknown:true}],Networks:[{Name:"payload",Payload:"test"}]};
const result=()=>({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"vip-snipher-pro",
  structuredJson:document,rawText:JSON.stringify(document),isPartial:false,warnings:[],exporterCertified:false});
test("VIP internal worker result preserves the complete offline document and rejects partial output",async t=>{
  const previous=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(previous===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=previous;});
  const input={providerId:"vip-snipher-pro"},settings={workerToken:"w".repeat(48)};
  const response=await fetchWorker("server-vpn",input,settings,{fetchImpl:async()=>Response.json(result())});
  assert.deepEqual((await response.json()).structuredJson,document);
  for(const bad of [
    {...result(),providerId:"other"},{...result(),kind:"file"},
    {...result(),isPartial:true},{...result(),rawText:"not JSON"},
    {...result(),rawText:JSON.stringify({...document,Networks:[]})},
    {...result(),rawText:JSON.stringify({...document,Servers:[]}),structuredJson:{...document,Servers:[]}},
    {...result(),rawText:JSON.stringify({...document,Networks:[1]}),structuredJson:{...document,Networks:[1]}},
  ])await assert.rejects(()=>fetchWorker("server-vpn",input,settings,{fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
});

function network(t,{data=Buffer.from("synthetic encrypted catalog"),location,check=()=>{}}={}){
  t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
  t.mock.method(https,"request",(url,options,callback)=>{
    check(url,options);
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=location?302:200;response.headers=location?{location}:{};
      callback(response);
      if(!location){response.emit("data",data);response.emit("end");}
    });return req;
  });
}
test("VIP fixed GET carries its secret only to the APK source",async t=>{
  enabled(t);const data=Buffer.from("synthetic encrypted VIP response");
  let count=0;
  network(t,{data,check:(url,options)=>{
    count++;
    assert.equal(options.method,"GET");assert.equal(options.rejectUnauthorized,true);
    assert.equal(options.headers["Accept-Encoding"],"identity");
    if(count===1){
      assert.equal(url.href,source);
      assert.equal(options.headers.Authorization,secret);
      assert.equal(options.headers.Accept,"application/json");
      assert.equal(options.headers["X-GitHub-Api-Version"],"2022-11-28");
    }else assert.equal(options.headers.Authorization,undefined);
  }});
  assert.deepEqual(await downloadVpnCatalog("vip-snipher-pro"),data);
  await downloadVpnCatalog("netcol-vpn");
  assert.equal(count,2);
  await assert.rejects(()=>downloadVpnCatalog("vip-snipher-pro","https://attacker.invalid/"),{code:"UNSUPPORTED_FORMAT"});
  assert.equal(count,2);
});
test("VIP rejects private DNS and all redirects before forwarding authorization",async t=>{
  enabled(t);
  t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
  t.mock.method(https,"request",()=>{throw Error("unexpected transport");});
  await assert.rejects(()=>downloadVpnCatalog("vip-snipher-pro"),{code:"REMOTE_NETWORK_DENIED"});
  for(const location of ["https://raw.githubusercontent.com/other/repo/main/file", "https://attacker.invalid/"]){
    let calls=0;
    network(t,{location,check:(url)=>{calls++;assert.equal(url.href,source);}});
    await assert.rejects(()=>downloadVpnCatalog("vip-snipher-pro"),{code:"REMOTE_NETWORK_DENIED"});
    assert.equal(calls,1);
  }
});
test("VIP persistent switch preserves other providers and never stores the secret",async t=>{
  const root=await mkdtemp(join(tmpdir(),"spdecode-vip-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",SPDECODE_VIP_SNIPHER_AUTHORIZATION:secret};
  await updateProvider("netcol-vpn",false,env,{root});
  await updateProvider("vip-snipher-pro",false,env,{root});
  assert.equal(await providerAllowed("vip-snipher-pro",env,{root}),false);
  const status=await updateProvider("vip-snipher-pro",true,env,{root});
  assert.equal(await providerAllowed("vip-snipher-pro",env,{root}),true);
  assert.equal(await providerAllowed("netcol-vpn",env,{root}),false);
  assert(!JSON.stringify(status).includes(secret));
  const missing=await providerOverview({...env,SPDECODE_VIP_SNIPHER_AUTHORIZATION:""},{root});
  assert.equal(missing.providers.find(x=>x.id==="vip-snipher-pro").configured,false);
  await assert.rejects(()=>updateProvider("vip-snipher-pro",true,{...env,SPDECODE_VIP_SNIPHER_AUTHORIZATION:""},{root}),/PROVIDER_NOT_CONFIGURED/);
});
test("authenticated VIP gateway forwards the complete catalog without forwarding its source credential",async t=>{
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
    SPDECODE_VIP_SNIPHER_AUTHORIZATION:secret,
    CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
    CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
    CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
  for(const [key,value] of Object.entries(env)){
    const old=process.env[key];process.env[key]=value;
    t.after(()=>{if(old===undefined)delete process.env[key];else process.env[key]=old;});
  }
  const now=Math.floor(Date.now()/1000),jti=randomUUID();
  const body=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
  const token=body+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(body).digest("base64url");
  const values=new Map([["spc3:session:"+jti,"1"]]);
  const redis={get:async key=>values.get(key)??null,
    incr:async key=>{const n=Number(values.get(key)||0)+1;values.set(key,String(n));return n;},
    expire:async()=>1,eval:async()=>1,zRem:async()=>1};
  const data=Buffer.from("synthetic encrypted VIP catalog");network(t,{data});
  const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify({id:"vip-snipher-pro",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    assert(!options.body.includes(secret));assert(!JSON.stringify(options.headers).includes(secret));
    const input=JSON.parse(options.body);assert.equal(input.providerId,"vip-snipher-pro");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),data);
    return Response.json(result());
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const output=await response.json();assert.equal(output.isPartial,false);
  assert.deepEqual(output.structuredJson,document);assert(!JSON.stringify(output).includes(secret));
});
