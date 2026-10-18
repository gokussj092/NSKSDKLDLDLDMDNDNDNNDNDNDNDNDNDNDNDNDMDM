import assert from "node:assert/strict";
import { test } from "node:test";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, createCipheriv, createHmac } from "node:crypto";
import { deflateSync } from "node:zlib";
import {
  parseEhiReference, approvedUrl, publicIpv4, pinnedAddresses,
  downloadApproved, buildEhiRequest, unwrapEhiResponse,
  importEhiReference, downloadNur, ehiConfigured, nurConfigured, EHI_ENDPOINT,
} from "../lib/c35-provider.mjs";
import { externalImportRequest } from "../lib/c35-gateway.mjs";
import { createChallenge, issueSession } from "../lib/c3-session.mjs";

const SIGN_KEY="S".repeat(32),RESPONSE_KEY="R".repeat(32);
const nurUrl="https://strongteam.co/synthetic-private-catalog";
const env={
  CLOUD_EHI_IMPORT_ENABLED:"true",CLOUD_EHI_SIGN_KEY:SIGN_KEY,
  CLOUD_EHI_RESPONSE_KEY:RESPONSE_KEY,CLOUD_NUR_FETCH_ENABLED:"true",
  CLOUD_NUR_CATALOG_URL:nurUrl,
};
const keyPair=generateKeyPairSync("rsa",{modulusLength:2048});
Object.assign(process.env,{
  CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"w".repeat(48),
  CLOUD_SESSION_SIGNING_KEY:"z".repeat(48),
  CLOUD_REDIS_URL:"redis://redis:6379",CLOUD_TRUST_PROXY:"true",
  CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify({
    type:"service_account",client_email:"synthetic@example.invalid",
    private_key:keyPair.privateKey.export({type:"pkcs8",format:"pem"}),
  }),
  WORKER_INTERNAL_URL:"http://decoder-worker:8787",
  ...env,
});
class FakeRedis{
  constructor(){this.values=new Map();this.count=new Map();this.active=new Map();}
  async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
  async get(k){return this.values.get(k)??null;}
  async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
  async incr(k){const c=(this.count.get(k)||0)+1;this.count.set(k,c);return c;}
  async expire(){return 1;}
  async eval(_,args){
    const k=args.keys[0],ids=this.active.get(k)||new Map();
    if(ids.size>=2)return 0;ids.set(args.arguments[0],Date.now());this.active.set(k,ids);
    return 1;
  }
  async zRem(k,id){this.active.get(k)?.delete(id);return 1;}
}
function send(body,token){
  return new Request("https://spdecode.test/api/v1/decode/import/cloud",{
    method:"POST",headers:{"Content-Type":"application/json",
      "X-Real-IP":"203.0.113.25",...(token?{Authorization:"Bearer "+token}:{})},
    body:JSON.stringify(body),
  });
}
async function token(redis){
  const challenge=await createChallenge(redis,send({}));
  assert.ok(challenge.nonce);
  const session=await issueSession(redis,send({}),{
    challengeId:challenge.challengeId,integrityToken:"I".repeat(100),
  },{
    signingKey:process.env.CLOUD_SESSION_SIGNING_KEY,
  },async()=>true);
  assert.ok(session.accessToken);
  return session.accessToken;
}
function syntheticResponse(responseKey=RESPONSE_KEY){
  const configData=Buffer.alloc(32,9);
  const plain=Buffer.from(JSON.stringify({status:"success",config_data:configData.toString("base64")}));
  const compressed=deflateSync(plain);
  const iv=Buffer.from(Array.from({length:16},(_,i)=>i));
  const cipher=createCipheriv("aes-256-cbc",Buffer.from(responseKey),iv);
  const encrypted=Buffer.concat([cipher.update(compressed),cipher.final()]);
  const tag=createHmac("sha256",Buffer.from(responseKey)).update(encrypted).digest();
  const envelope=Buffer.concat([iv,tag,encrypted]);
  return Buffer.from(JSON.stringify({code:200,data:envelope.toString("base64")}));
}
test("only exact EHI reference formats are accepted, including the Android emoji vector",()=>{
  for(const value of ["TEST1234","https://ehi.link/TEST1234","ehi://ehi.link/TEST1234",
    "💉😩😘😩😧😩😗😘🙌😠🙍😤😐🚀"]){
      assert.equal(parseEhiReference(value),"TEST1234");
  }
  for(const value of ["http://ehi.link/TEST1234","https://ehi.link:444/TEST1234",
    "https://ehi.link@evil.example/TEST1234","https://ehi.link/TEST1234?url=http://127.0.0.1",
    "https://ehi.link/A%2fB","https://evil.example/x","file:///etc/passwd",
    "http://169.254.169.254/latest","💉😩🚀","💉💩🚀"]){
      assert.throws(()=>parseEhiReference(value),{code:"INVALID_REFERENCE"},value);
  }
});
test("external destinations are code allowlisted, with no custom ports or credentials",()=>{
  assert.equal(approvedUrl(EHI_ENDPOINT,"ehi").hostname,"www.ehi.tools");
  assert.equal(approvedUrl(nurUrl,"nur").hostname,"strongteam.co");
  for(const url of ["http://127.0.0.1/","https://[::1]/",
    "https://www.ehi.tools@169.254.169.254/import",
    "https://www.ehi.tools:444/httpinjector/import_config",
    "https://www.ehi.tools/anything","https://www.ehi.tools/httpinjector/import_config?next=127.0.0.1",
    "https://strongteam.co.evil.example/test"]){
    assert.throws(()=>approvedUrl(url,"ehi"),{code:"REMOTE_NETWORK_DENIED"});
  }
  assert.throws(()=>approvedUrl("https://evil.example/catalog","nur"),{code:"REMOTE_NETWORK_DENIED"});
});
test("DNS public IPv4 policy blocks reserved, local, cloud metadata, benchmark and CGNAT",async()=>{
  for(const ip of ["127.0.0.1","10.1.2.3","172.31.250.1","192.168.1.1",
    "169.254.169.254","100.64.0.1","0.0.0.0","192.0.2.4",
    "198.51.100.1","203.0.113.7","198.19.3.1","224.0.0.1",
    "255.255.255.255","::1","::ffff:127.0.0.1"]){
    assert.equal(publicIpv4(ip),false,ip);
  }
  assert.equal(publicIpv4("8.8.8.8"),true);
  assert.deepEqual(await pinnedAddresses("www.ehi.tools",async()=>[{address:"8.8.8.8",family:4}]),["8.8.8.8"]);
  await assert.rejects(
    ()=>pinnedAddresses("www.ehi.tools",async()=>[{address:"8.8.8.8",family:4},{address:"127.0.0.1",family:4}]),
    {code:"REMOTE_NETWORK_DENIED"},
  );
  await assert.rejects(()=>pinnedAddresses("localhost",async()=>[{address:"8.8.8.8",family:4}]),
    {code:"REMOTE_NETWORK_DENIED"});
  await assert.rejects(()=>pinnedAddresses("strongteam.co",async()=>[]),
    {code:"REMOTE_NETWORK_DENIED"});
});
function fakeTransport(statusCode=200,payload=Buffer.from("test"),headers={}){
  return (url,options,onResponse)=>{
    const req=new EventEmitter();
    req.write=()=>{};
    req.end=()=>{
      queueMicrotask(()=>{
        assert.equal(options.rejectUnauthorized,true);
        assert.equal(options.agent,false);
        assert.equal(options.headers["Accept-Encoding"],"identity");
        options.lookup(url.hostname,{},(error,ip,family)=>{
          assert.ifError(error);assert.equal(ip,"8.8.8.8");assert.equal(family,4);
        });
        const res=new EventEmitter();
        res.statusCode=statusCode;res.headers=headers;
        res.destroy=()=>{};onResponse(res);
        if(statusCode===200){res.emit("data",payload);res.emit("end");}
      });
    };
    req.destroy=()=>{};
    return req;
  };
}
test("actual HTTPS transport pins checked address and rejects redirects and oversized bodies",async()=>{
  const opts={resolve:async()=>[{address:"8.8.8.8",family:4}]};
  const fetched=await downloadApproved({url:EHI_ENDPOINT,kind:"ehi",method:"POST",body:"x"},{
    ...opts,request:fakeTransport(200,Buffer.from("abc")),
  });
  assert.equal(fetched.toString(),"abc");
  await assert.rejects(()=>downloadApproved({url:EHI_ENDPOINT,kind:"ehi"},{
    ...opts,request:fakeTransport(302),
  }),{code:"REMOTE_PROVIDER_UNAVAILABLE"});
  await assert.rejects(()=>downloadApproved({url:EHI_ENDPOINT,kind:"ehi",maxBytes:2},{
    ...opts,request:fakeTransport(200,Buffer.from("oversized")),
  }),{code:"REMOTE_TOO_LARGE"});
  await assert.rejects(()=>downloadApproved({url:EHI_ENDPOINT,kind:"ehi"},{
    ...opts,request:fakeTransport(200,Buffer.from("abc"),{"content-encoding":"gzip"}),
  }),{code:"REMOTE_RESPONSE_INVALID"});
});
test("NUR mirrors Python 30-second/16-MiB download contract without weakening EHI",async()=>{
  const opts={resolve:async()=>[{address:"8.8.8.8",family:4}]};
  const large=Buffer.alloc(8*1024*1024+1,65);
  const content=await downloadApproved({
    url:nurUrl,kind:"nur",method:"GET",maxBytes:16*1024*1024,
  },{...opts,request:fakeTransport(200,large)});
  assert.equal(content.length,large.length);
  await assert.rejects(()=>downloadApproved({
    url:nurUrl,kind:"nur",method:"GET",maxBytes:16*1024*1024+1,
  },{...opts,request:fakeTransport()}),{code:"REMOTE_NETWORK_DENIED"});
  await assert.rejects(()=>downloadApproved({
    url:EHI_ENDPOINT,kind:"ehi",method:"POST",maxBytes:16*1024*1024,
  },{...opts,request:fakeTransport()}),{code:"REMOTE_NETWORK_DENIED"});
});
test("NUR accepts bounded same-host HTTPS redirects but rejects other origins, protocols and loops",async()=>{
  const opts={resolve:async()=>[{address:"8.8.8.8",family:4}]};
  let calls=0;
  const request=(...args)=>{
    calls++;
    return fakeTransport(calls===1?302:200,Buffer.from("NUR"),calls===1?
      {"location":"/catalog/updated"}:{})(...args);
  };
  const output=await downloadApproved({url:nurUrl,kind:"nur",method:"GET"},{
    ...opts,request,
  });
  assert.equal(output.toString(),"NUR");
  assert.equal(calls,2);
  for(const target of [
    "https://evil.example/private","http://strongteam.co/catalog",
    "https://strongteam.co:444/path","https://strongteam.co/catalog?secret=1",
    "https://strongteam.co@evil.example/catalog","https://127.0.0.1/",
  ]){
    await assert.rejects(()=>downloadApproved({url:nurUrl,kind:"nur"},{
      ...opts,request:fakeTransport(302,Buffer.from(""),{"location":target}),
    }),{code:"REMOTE_NETWORK_DENIED"},target);
  }
  await assert.rejects(()=>downloadApproved({url:nurUrl,kind:"nur"},{
    ...opts,request:fakeTransport(302,Buffer.from(""),{"location":"/catalog/updated"}),
  }),{code:"REMOTE_PROVIDER_UNAVAILABLE"});
});
test("NUR returns safe HTTP status reason for operator diagnostics only",async()=>{
  await assert.rejects(()=>downloadApproved({url:nurUrl,kind:"nur"},{
    resolve:async()=>[{address:"8.8.8.8",family:4}],
    request:fakeTransport(403),
  }),err=>err.code==="REMOTE_PROVIDER_UNAVAILABLE" && err.reason==="HTTP_403");
});
test("signed HTTP Injector request cannot be redirected to arbitrary URLs",()=>{
  const result=buildEhiRequest("TEST1234",{signKey:SIGN_KEY,
    now:1700000000,nonce:"00000000-0000-4000-8000-000000000000",
    identity:"identity-synthetic"});
  assert.equal(result.url,EHI_ENDPOINT);
  assert.equal(result.method,"POST");
  assert.equal(result.body.toString(),"config_key=TEST1234");
  assert.equal(result.headers["x-platform"],"android");
  assert.equal(result.headers["x-app-build"],"244");
  assert.match(result.headers["x-signature"],/^[A-Za-z0-9%]+$/);
  assert.throws(()=>buildEhiRequest("../../../etc/passwd",{signKey:SIGN_KEY}),
    {code:"INVALID_REFERENCE"});
});
test("C3.5 signed request is byte-compatible with the existing Android synthetic vector",()=>{
  const android=readFileSync(new URL("../../../android/app/src/main/java/com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt",import.meta.url),"utf8");
  const match=/private const val SIGN_KEY = "([^"]+)"/.exec(android);
  assert.ok(match,"Existing authorized Android protocol reference unavailable");
  const signed=buildEhiRequest("TEST1234",{
    signKey:match[1],now:1700000000,
    nonce:"00000000-0000-4000-8000-000000000000",
    identity:"identity-synthetic",
  });
  assert.equal(signed.headers["x-signature"],"03p7UQBNZXTELXW82PMwoNeyta0%3D");
});
test("HTTP Injector response MAC and AES/zlib integrity precede EHI processing",()=>{
  const valid=syntheticResponse();
  const result=unwrapEhiResponse(valid,{responseKey:RESPONSE_KEY});
  assert.equal(result.readUInt16BE(0),3);
  assert.equal(result.toString("ascii",2,5),"ehi");
  assert.equal(result.toString("ascii",15,18),"244");
  assert.equal(result.readUInt32BE(26),32);
  assert.equal(result.subarray(-32).equals(Buffer.alloc(32,9)),true);
  const outer=JSON.parse(valid);
  const corrupted=Buffer.from(outer.data,"base64");corrupted[22]^=1;
  outer.data=corrupted.toString("base64");
  assert.throws(()=>unwrapEhiResponse(Buffer.from(JSON.stringify(outer)),{responseKey:RESPONSE_KEY}),
    {code:"REMOTE_INTEGRITY_FAILED"});
  assert.throws(()=>unwrapEhiResponse(valid,{responseKey:"Q".repeat(32)}),
    {code:"REMOTE_INTEGRITY_FAILED"});
  assert.throws(()=>unwrapEhiResponse(Buffer.from('{"code":401}'),{responseKey:RESPONSE_KEY}),
    {code:"REMOTE_PROVIDER_UNAVAILABLE"});
  assert.throws(()=>unwrapEhiResponse(Buffer.from('{"code":200,"data":"AA=="}'),{responseKey:RESPONSE_KEY}),
    {code:"REMOTE_RESPONSE_INVALID"});
});
test("remote provider flags fail closed without server-only keys and exact NUR origin",()=>{
  assert.equal(ehiConfigured({}),false);
  assert.equal(nurConfigured({}),false);
  assert.equal(ehiConfigured({...env,CLOUD_EHI_SIGN_KEY:"short"}),false);
  assert.equal(nurConfigured({...env,CLOUD_NUR_CATALOG_URL:"http://127.0.0.1"}),false);
  assert.equal(ehiConfigured(env),true);
  assert.equal(nurConfigured(env),true);
  assert.rejects(()=>downloadNur({env:{...env,CLOUD_NUR_CATALOG_URL:"https://127.0.0.1/latest"}}),
    {code:"REMOTE_NOT_CONFIGURED"});
});
test("C3.5 imports require an attested bearer and user consent BEFORE any remote fetch",async()=>{
  const redis=new FakeRedis();let networkCalls=0,workerCalls=0;
  const fakeVendor={env,transport:async({url,kind})=>{
    networkCalls++;assert.equal(kind,"ehi");assert.equal(url,EHI_ENDPOINT);
    return syntheticResponse();
  }};
  const fetchImpl=async(url,options)=>{
    workerCalls++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/file");
    const data=JSON.parse(options.body);
    assert.equal(data.format,"ehi");
    assert.equal(Buffer.from(data.dataBase64,"base64").toString("ascii",2,5),"ehi");
    return {status:200,text:async()=>JSON.stringify({
      apiVersion:"v1",status:"success",rawText:"full decoded config\n",
      structuredJson:null,isPartial:false,warnings:[],
    })};
  };
  const options={storeProvider:async()=>redis,vendor:fakeVendor,fetchImpl};
  const without=await externalImportRequest(send({reference:"TEST1234",consent:true}),"ehi",options);
  assert.equal(without.status,401);
  const bearer=await token(redis);
  const noConsent=await externalImportRequest(send({reference:"TEST1234",consent:false},bearer),"ehi",options);
  assert.equal(noConsent.status,400);
  const attack=await externalImportRequest(send({reference:"https://127.0.0.1/private",consent:true},bearer),"ehi",options);
  assert.equal(attack.status,400);
  assert.equal(networkCalls,0);assert.equal(workerCalls,0);
  const ok=await externalImportRequest(send({reference:"TEST1234",consent:true},bearer),"ehi",options);
  assert.equal(ok.status,200);
  assert.equal((await ok.json()).rawText,"full decoded config\n");
  assert.equal(networkCalls,1);assert.equal(workerCalls,1);
});
test("NUR catalog download endpoint never accepts client URLs or unconsented requests",async()=>{
  const redis=new FakeRedis(),bearer=await token(redis);
  let calls=0;
  const vendor={env,transport:async({url,kind})=>{
    assert.equal(url,nurUrl);assert.equal(kind,"nur");calls++;
    return Buffer.from("encrypted synthetic catalog");
  }};
  const fetchImpl=async(url,options)=>{
    assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/import/catalog");
    const payload=JSON.parse(options.body);
    assert.equal(Buffer.from(payload.dataBase64,"base64").toString(),"encrypted synthetic catalog");
    return {status:200,text:async()=>JSON.stringify({status:"success",
      rawText:'{"Version":"demo","Servers":[],"Networks":[]}',structuredJson:{Version:"demo",Servers:[],Networks:[]},
      isPartial:false,warnings:[]})};
  };
  const options={storeProvider:async()=>redis,vendor,fetchImpl};
  assert.equal((await externalImportRequest(send({consent:true,url:"http://169.254.169.254"},bearer),"nur",options)).status,400);
  assert.equal((await externalImportRequest(send({consent:false},bearer),"nur",options)).status,400);
  assert.equal(calls,0);
  const result=await externalImportRequest(send({consent:true},bearer),"nur",options);
  assert.equal(result.status,200);
  assert.equal(calls,1);
});
