import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import dns from "node:dns/promises";
import https from "node:https";
import {createHmac,randomUUID} from "node:crypto";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {EventEmitter} from "node:events";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {catalog,iconFor,CATALOG_VERSION,activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {updateProvider,providerAllowed,PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";

const id="genis-vpn",source="https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis";
const fixtures=new URL("../../../analysis/com.doriaxvip.tunnel/76/tests/fixtures/",import.meta.url);
const expected=JSON.parse(fs.readFileSync(new URL("catalog.json",fixtures)));

function network(t,{address="93.184.216.34",status=200}={}){
  const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
  const seen=[];
  t.mock.method(dns,"lookup",async()=>[{address,family:4}]);
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,source);seen.push(url.href);
    assert.equal(options.method,"GET");assert.equal(options.rejectUnauthorized,true);
    assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0 (Linux; U; Android 14)");
    assert.equal(options.headers["Accept-Encoding"],"identity");assert.equal(options.headers.Authorization,undefined);
    options.lookup(url.hostname,{},(error,ip)=>{assert.equal(error,null);assert.equal(ip,address);});
    const request=new EventEmitter();request.destroy=()=>{};
    request.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.statusCode=status;
      response.headers=status===302?{location:source+"/other"}:{};response.resume=()=>{};
      callback(response);
      if(status===200){response.emit("data",fs.readFileSync(new URL("catalog.enc",fixtures)));response.emit("end");}
    });return request;
  });return seen;
}

test("Genis downloads only its fixed original source over pinned TLS",async t=>{
  const seen=network(t);
  assert.deepEqual(await downloadVpnCatalog(id),fs.readFileSync(new URL("catalog.enc",fixtures)));
  assert.equal(seen.length,1);
  for(const input of ["users","https://example.org/"])await assert.rejects(()=>downloadVpnCatalog(id,input),{code:"UNSUPPORTED_FORMAT"});
});

test("Genis denies private DNS and every redirect",async t=>{
  const seen=network(t,{status:302});
  await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});assert.equal(seen.length,1);
  t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
  await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_NETWORK_DENIED"});assert.equal(seen.length,1);
});

test("Genis source failure never returns the included catalog",async t=>{
  const seen=network(t,{status:404});
  await assert.rejects(()=>downloadVpnCatalog(id),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.equal(seen.length,1);
});

test("Genis original launcher pixels, metadata and monotonic public catalog",()=>{
  assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));
  assert.equal(CATALOG_VERSION,73);assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"215686715"}),215686715);
  const doc=catalog(),app=doc.apps.find(x=>x.id===id);
  assert.equal(doc.apps.length,67);assert.equal(doc.formats.length,256);assert.equal(app.name,"Genis VPN");
  assert.equal(app.iconSha256,"ae3cc43d7f773363966b9afa2e981f0deee5e8c96d2611a2f8b768581311756b");
  assert.equal(iconFor(id).bytes.length,20306);assert(!JSON.stringify(app).includes("https://"));
  assert.equal(catalog({availability:{[id]:false}}).apps.find(x=>x.id===id).decodeEnabled,false);
});

test("Genis switch preserves earlier provider choices",async t=>{
  const root=await mkdtemp(join(tmpdir(),"genis-control-"));t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("netcol-vpn",false,env,{root});await updateProvider(id,false,env,{root});
  assert.equal(await providerAllowed(id,env,{root}),false);await updateProvider(id,true,env,{root});
  assert.equal(await providerAllowed(id,env,{root}),true);assert.equal(await providerAllowed("netcol-vpn",env,{root}),false);
});

test("Genis gateway requires matching complete server JSON",async t=>{
  const old=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(old===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=old;});
  const good={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:id,structuredJson:expected,
    rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false};
  const call=value=>fetchWorker("server-vpn",{providerId:id},{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(value)});
  assert.deepEqual((await(await call(good)).json()).structuredJson,expected);
  for(const bad of [{...good,isPartial:true},{...good,providerId:"http-conexion"},{...good,rawText:"{}"},
                    {...good,kind:"text"}])await assert.rejects(()=>call(bad),/INVALID_WORKER_RESULT/);
  for(const change of [d=>d.Servers=[],d=>d.Servers=[{}],d=>d.Version=1,d=>d.ReleaseNotes={},d=>d.Usuarios=[{}]]){
    const doc=structuredClone(expected);change(doc);
    await assert.rejects(()=>call({...good,structuredJson:doc,rawText:JSON.stringify(doc)}),/INVALID_WORKER_RESULT/);
  }
});

test("authenticated Genis broker forwards all bytes and returns the complete worker document",async t=>{
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
  const bytes=fs.readFileSync(new URL("catalog.enc",fixtures));
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"raw.githubusercontent.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis");
    assert.equal(options.headers["User-Agent"],"Dalvik/2.1.0 (Linux; U; Android 14)");
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
    body:JSON.stringify({id:"genis-vpn",consent:true}),
  });
  let calls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    calls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/server-vpn");
    const input=JSON.parse(options.body);assert.equal(input.providerId,"genis-vpn");
    assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:id,structuredJson:expected,rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false}));
  }});
  assert.equal(response.status,200);assert.equal(calls,1);
  const result=await response.json();assert.equal(result.isPartial,false);
  assert.deepEqual(result.structuredJson,expected);assert.deepEqual(JSON.parse(result.rawText),expected);
});

