import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {gunzipSync} from "node:zlib";
import fs from "node:fs";
import {createHmac,randomUUID} from "node:crypto";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {createHttpConexionResolver,httpConexionResolver,selectHttpConexionConfig,packHttpConexionCatalog,
  HTTP_CONEXION_FIREBASE_OPTIONS as options} from "../lib/http-conexion-firebase.mjs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

const source="https://raw.githubusercontent.com/soportecrisdev/Gen/main/rotated";
const config=password=>({entries:{ockla_url:source,gretta_pass:password}});
const installation={fid:"c"+"A".repeat(21),refreshToken:"synthetic-refresh",authToken:{token:"synthetic-issued"}};
const bytes=value=>Buffer.from(JSON.stringify(value));

test("HTTP Conexión selects URL/password together and rejects unapproved sources",()=>{
  assert.deepEqual(selectHttpConexionConfig(config("new-©-password")),{source,password:"new-©-password"});
  for(const url of ["http://raw.githubusercontent.com/a/b/main/x","https://127.0.0.1/a/b/main/x",source+"?x=1",
                    source+"#x","https://raw.githubusercontent.com@attacker.invalid/a/b/main/x",source+"\n",
                    "https://raw.githubusercontent.com:443/a/b/main/x"])
    assert.throws(()=>selectHttpConexionConfig({entries:{ockla_url:url,gretta_pass:"x"}}));
  for(const reply of [{},{entries:{}},{entries:{ockla_url:source}},{entries:{ockla_url:source,gretta_pass:""}}])
    assert.throws(()=>selectHttpConexionConfig(reply));
});

test("FIS-issued token stays on Google; each temporary installation is deleted",async()=>{
  const resolver=createHttpConexionResolver(),calls=[];
  const request=async(url,o)=>{
    calls.push({url,o});
    if(url.endsWith("/installations")){
      const body=JSON.parse(gunzipSync(o.body));assert.equal(body.appId,options.app_id);
      assert.equal(body.authVersion,"FIS_v2");assert.equal(o.headers.Authorization,undefined);return bytes(installation);
    }
    if(url.endsWith("firebase:fetch")){
      assert.equal(o.headers["X-Goog-Firebase-Installations-Auth"],"synthetic-issued");
      assert.equal(JSON.parse(o.body).appInstanceIdToken,"synthetic-issued");return bytes(config("fresh-password"));
    }
    assert.equal(o.method,"DELETE");assert.equal(o.headers.Authorization,"FIS_v2 synthetic-refresh");return Buffer.alloc(0);
  };
  assert.deepEqual(await resolver.get(request),{source,password:"fresh-password"});assert.equal(calls.length,3);
  assert(calls.every(x=>new URL(x.url).hostname.endsWith("googleapis.com")));
});

test("concurrent clients share one config fetch and one immutable pair",async()=>{
  const resolver=createHttpConexionResolver();let calls=0;
  const request=async(url,o)=>{calls++;return url.endsWith("/installations")?bytes(installation):o.method==="DELETE"?Buffer.alloc(0):bytes(config("one"));};
  const results=await Promise.all(Array.from({length:12},()=>resolver.get(request)));
  assert.equal(calls,3);assert(results.every(x=>x===results[0]));assert(Object.isFrozen(results[0]));
});

test("TTL and forced refresh replace the pair; failure has a cooldown and no stale fallback",async t=>{
  let now=1000,password="one",calls=0,bad=false;
  t.mock.method(Date,"now",()=>now);const resolver=createHttpConexionResolver();
  const request=async(url,o)=>{calls++;if(url.endsWith("/installations"))return bytes(installation);if(o.method==="DELETE")return Buffer.alloc(0);return bytes(bad?{}:config(password));};
  assert.equal((await resolver.get(request)).password,"one");password="two";
  assert.equal((await resolver.get(request)).password,"one");assert.equal(calls,3);
  assert.equal((await resolver.get(request,{force:true})).password,"two");assert.equal(calls,6);
  now+=3600001;password="three";assert.equal((await resolver.get(request)).password,"three");assert.equal(calls,9);
  bad=true;await assert.rejects(()=>resolver.get(request,{force:true}));assert.equal(calls,12);
  await assert.rejects(()=>resolver.get(request));assert.equal(calls,12);
});

test("invalid Remote Config still cleans up and never uses fixed legacy values",async()=>{
  const resolver=createHttpConexionResolver(),calls=[];
  const request=async(url,o)=>{calls.push(o.method);return url.endsWith("/installations")?bytes(installation):o.method==="DELETE"?Buffer.alloc(0):bytes({entries:{ockla_url:source}});};
  await assert.rejects(()=>resolver.get(request),/HTTP_CONEXION_FIREBASE_UNAVAILABLE/);assert.deepEqual(calls,["POST","POST","DELETE"]);
});

test("broker resolves metadata through pinned TLS then wraps the exact new source and password",async t=>{
  const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";httpConexionResolver.clear();
  t.after(()=>{httpConexionResolver.clear();if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
  const seen=[];t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
  t.mock.method(https,"request",(url,o,callback)=>{
    assert.equal(o.rejectUnauthorized,true);assert.equal(o.headers["Accept-Encoding"],"identity");
    o.lookup(url.hostname,{},(error,ip)=>{assert.equal(error,null);assert.equal(ip,"93.184.216.34");});
    const req=new EventEmitter();req.destroy=()=>{};req.end=body=>queueMicrotask(()=>{
      seen.push(url.href);let data;
      if(url.pathname.endsWith("/installations")){assert.equal(o.method,"POST");assert.equal(JSON.parse(gunzipSync(body)).appId,options.app_id);data=bytes(installation);}
      else if(url.pathname.endsWith("firebase:fetch")){assert.equal(o.headers["X-Goog-Firebase-Installations-Auth"],"synthetic-issued");data=bytes(config("rotated-©-password"));}
      else if(o.method==="DELETE"){assert.equal(o.headers.Authorization,"FIS_v2 synthetic-refresh");data=Buffer.alloc(0);}
      else{
        assert.equal(url.origin+url.pathname,source);assert(url.searchParams.has("nocache"));
        assert.equal(o.headers["X-Goog-Api-Key"],undefined);assert.equal(o.headers.Authorization,undefined);
        assert.equal(o.headers["X-Goog-Firebase-Installations-Auth"],undefined);data=Buffer.from("fictional-catalog-body");
      }
      const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};callback(res);res.emit("data",data);res.emit("end");
    });return req;
  });
  const bundled=JSON.parse((await downloadVpnCatalog("http-conexion")).toString());assert.equal(seen.length,4);
  assert.equal(Buffer.from(bundled.passwordBase64,"base64").toString(),"rotated-©-password");
  assert.equal(Buffer.from(bundled.catalogBase64,"base64").toString(),"fictional-catalog-body");
});

test("broker rejects private Google DNS before sending Firebase options",async t=>{
  const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";httpConexionResolver.clear();
  t.after(()=>{httpConexionResolver.clear();if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
  t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
  t.mock.method(https,"request",()=>{throw Error("unexpected transport");});
  await assert.rejects(()=>downloadVpnCatalog("http-conexion"),{code:"REMOTE_PROVIDER_UNAVAILABLE"});
});

test("internal bundle rejects oversized payloads and invalid passwords",()=>{
  for(const password of ["",null,"x\0y","x".repeat(1025)])assert.throws(()=>packHttpConexionCatalog(Buffer.from("x"),password));
  assert.throws(()=>packHttpConexionCatalog(Buffer.alloc(7*1024*1024),"fixture"),/BUNDLE_TOO_LARGE/);
});

for(const mode of ["rotation","source-moved","still-invalid"]){
  test(`authenticated HTTP Conexión ${mode} refreshes once and preserves the matching pair`,async t=>{
    const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
      CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
      CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
      CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
    for(const [key,value] of Object.entries(env)){
      const prior=process.env[key];process.env[key]=value;
      t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});
    }
    const forced=[];
    t.mock.method(httpConexionResolver,"get",async(_request,{force=false}={})=>{
      forced.push(force);return {source:source+(force?"-new":"-old"),password:force?"new-pair":"old-pair"};
    });
    let downloads=0;
    t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
    t.mock.method(https,"request",(url,o,callback)=>{
      assert.equal(o.headers.Authorization,undefined);assert.equal(o.headers["X-Goog-Api-Key"],undefined);
      assert.equal(url.origin+url.pathname,source+(downloads?"-new":"-old"));downloads++;
      const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
        const res=new EventEmitter();res.headers={};res.resume=()=>{};
        res.statusCode=mode==="source-moved"&&downloads===1?404:200;callback(res);
        if(res.statusCode===200){res.emit("data",Buffer.from("ciphertext-"+downloads));res.emit("end");}
      });return req;
    });
    const now=Math.floor(Date.now()/1000),jti=randomUUID();
    const claim=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
    const session=claim+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(claim).digest("base64url");
    const values=new Map([["spc3:session:"+jti,"1"]]);
    const redis={get:async key=>values.get(key)??null,incr:async key=>{const n=Number(values.get(key)||0)+1;values.set(key,String(n));return n;},
      expire:async()=>1,eval:async()=>1,zRem:async()=>1};
    const expected=JSON.parse(fs.readFileSync(new URL("../../../analysis/com.doriaxvpn.unlimited/129/tests/fixtures/expected.json",import.meta.url)));
    const request=new Request("https://api.example.test/api/v1/server-vpn/decode",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+session},body:JSON.stringify({id:"http-conexion",consent:true})});
    let calls=0;
    const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(_url,o)=>{
      const input=JSON.parse(o.body);const envelope=JSON.parse(Buffer.from(input.dataBase64,"base64"));
      assert.equal(Buffer.from(envelope.passwordBase64,"base64").toString(),downloads===1?"old-pair":"new-pair");calls++;
      if(mode==="still-invalid"||(mode==="rotation"&&calls===1))return Response.json({error:{code:"DECODE_FAILED"}},{status:422});
      return Response.json({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"http-conexion",structuredJson:expected,rawText:JSON.stringify(expected),isPartial:false,warnings:[],exporterCertified:false});
    }});
    assert.equal(downloads,2);assert.deepEqual(forced,[false,true]);
    assert.equal(response.status,mode==="still-invalid"?422:200);assert.equal(calls,mode==="source-moved"?1:2);
    if(response.ok)assert.deepEqual((await response.json()).structuredJson,expected);
    else assert(!JSON.stringify(await response.json()).includes("new-pair"));
  });
}
