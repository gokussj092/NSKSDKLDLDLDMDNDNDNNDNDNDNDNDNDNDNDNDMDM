import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {createHmac,randomUUID} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import dns from "node:dns/promises";
import https from "node:https";
import {catalog,iconFor,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {providerAllowed,updateProvider,providerOverview} from "../lib/c12-provider-controls.mjs";
import {parseMnrReference,mnrReferenceUrl,importMnrReference,approvedUrl,downloadApproved} from "../lib/c35-provider.mjs";
import {externalImportRequest} from "../lib/c35-gateway.mjs";
import {decodeRequest,fetchWorker} from "../lib/c3-gateway.mjs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";

const id="AbC123xyZ0",reference="mnrtunneludp://"+id;
const metadata={bucket:"hamovpn.firebasestorage.app",name:"mnrtunneludp:/"+id+".sky",downloadTokens:"synthetic-token,second"};
const profile={http_p:"example.invalid",TunnelType:6,isPassON:true,MyPass:"synthetic-only",DeviceID:"test",ExpireDate:1,unknown:{keep:[true,null]}};
const doc={Version:"synthetic",Servers:[{Name:"server",ServerIP:"example.invalid"}],Networks:[{Name:"net",wsPayload:true}],unknown:[1,false]};
const result=(obj,kind="file")=>({apiVersion:"v1",status:"success",kind,
  ...(kind==="vpn_catalog"?{providerId:"mnr-tunnel-plus"}:{}),structuredJson:obj,rawText:JSON.stringify(obj),isPartial:false,warnings:[]});

function session(t){
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
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
  const redis={get:async key=>values.get(key)??null,incr:async key=>{const n=Number(values.get(key)||0)+1;values.set(key,String(n));return n;},
    expire:async()=>1,eval:async()=>1,zRem:async()=>1};
  const request=(data,bearer=token)=>new Request("https://api.example.test/api/v1/decode/text",{
    method:"POST",headers:{"content-type":"application/json",...(bearer?{authorization:"Bearer "+bearer}:{})},body:JSON.stringify(data)});
  return {redis,request};
}

test("MNR catalog publishes the original icon, Cloud-only STP and persistent availability",async t=>{
  assert.equal(CATALOG_VERSION,59);
  const current=catalog({availability:{"mnr-tunnel-plus":true}});
  assert.equal(current.apps.length,56);
  const card=current.apps.find(x=>x.id==="mnr-tunnel-plus");
  assert.equal(card.name,"MNR TUNNEL PLUS");assert.equal(card.decodeEnabled,true);
  assert.equal(card.iconSha256,"ed99d8abdfbbcdd58c0a016d54299440d64c39608dd225674c0291f85d219b1a");
  assert.equal(iconFor(card.id).bytes.length,72125);
  assert.deepEqual(current.formats.find(x=>x.suffix==="stp"),{suffix:"stp",name:"MNR TUNNEL PLUS 3.1",kind:"file",offlineSupported:false,cloudSupported:true,credentialFields:[]});
  const root=await mkdtemp(join(tmpdir(),"spdecode-mnr-"));t.after(()=>rm(root,{recursive:true,force:true}));
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true"};
  await updateProvider("bd-net-vpn",false,env,{root});await updateProvider(card.id,false,env,{root});
  assert.equal(await providerAllowed(card.id,env,{root}),false);
  await updateProvider(card.id,true,env,{root});assert.equal(await providerAllowed(card.id,env,{root}),true);
  assert.equal((await providerOverview(env,{root})).providers.find(x=>x.id==="bd-net-vpn").enabled,false);
});

test("MNR reference maps to the exact normalized Firebase object and only its media query",()=>{
  assert.equal(parseMnrReference(reference),id);assert.equal(parseMnrReference(id),id);
  const url=mnrReferenceUrl(reference);assert.equal(url,mnrReferenceUrl(id));
  assert(url.endsWith("/o/mnrtunneludp%3A%2FAbC123xyZ0.sky"));
  assert.equal(approvedUrl(url,"mnr").hostname,"firebasestorage.googleapis.com");
  approvedUrl(url+"?alt=media&token=synthetic-token","mnr");
  for(const value of ["../abc",reference+".sky",reference+"/x",reference+"?url=x","https://127.0.0.1/a",id.toLowerCase()+"x"])
    assert.throws(()=>parseMnrReference(value),{code:"INVALID_REFERENCE"});
  for(const target of [url.replace("hamovpn.firebasestorage.app","other.appspot.com"),url.replace("https:","http:"),
    url.replace(".googleapis.com",".googleapis.com.attacker.invalid"),url+"?alt=media&token=x&url=http://127.0.0.1",url+"#fragment",
    url.replace("%3A%2F","%3A%2F%2F"),url.replace("/o/","/o/../")])
    assert.throws(()=>approvedUrl(target,"mnr"),{code:"REMOTE_NETWORK_DENIED"});
});

test("Firebase import uses metadata token then whole media body and refuses mismatched metadata",async()=>{
  const calls=[],bytes=Buffer.from("synthetic MNR ciphertext");
  const value=await importMnrReference(reference,{download:async request=>{
    calls.push(request);return calls.length===1?Buffer.from(JSON.stringify(metadata)):bytes;
  }});
  assert.deepEqual(value,bytes);assert.equal(calls.length,2);
  assert.equal(calls[0].url,mnrReferenceUrl(id));assert.equal(calls[0].maxBytes,256*1024);
  assert.equal(calls[1].url,mnrReferenceUrl(id)+"?alt=media&token=synthetic-token");
  for(const bad of [{...metadata,bucket:"other"},{...metadata,name:"other.sky"},{...metadata,downloadTokens:"x&url=evil"},{},null]){
    let seen=0;
    await assert.rejects(()=>importMnrReference(id,{download:async()=>{seen++;return Buffer.from(JSON.stringify(bad));}}),{code:"REMOTE_RESPONSE_INVALID"});
    assert.equal(seen,1);
  }
});

function network(t,{status=200,headers={},data=Buffer.from("whole payload")}={}){
  let opened=0;
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"firebasestorage.googleapis.com");return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    opened++;assert.equal(url.hostname,"firebasestorage.googleapis.com");assert.equal(options.rejectUnauthorized,true);
    options.lookup(url.hostname,{all:true},(err,answers)=>{assert.equal(err,null);assert.equal(answers[0].address,"93.184.216.34");});
    const req=new EventEmitter();req.destroy=()=>{};
    req.end=()=>queueMicrotask(()=>{
      const res=new EventEmitter();res.destroy=()=>{};res.statusCode=status;res.headers=headers;callback(res);
      res.emit("data",data);res.emit("end");
    });return req;
  });
  return ()=>opened;
}

test("MNR transport pins public DNS and TLS, and passes every response byte",async t=>{
  const opened=network(t);assert.deepEqual(await downloadApproved({url:mnrReferenceUrl(id),kind:"mnr"}),Buffer.from("whole payload"));assert.equal(opened(),1);
});
test("MNR transport refuses private DNS before opening a socket",async t=>{
  t.mock.method(dns,"lookup",async()=>[{address:"127.0.0.1",family:4}]);
  t.mock.method(https,"request",()=>assert.fail("socket must stay closed"));
  await assert.rejects(()=>downloadApproved({url:mnrReferenceUrl(id),kind:"mnr"}),{code:"REMOTE_NETWORK_DENIED"});
});
test("MNR transport refuses redirects, missing references, compression and byte excess",async t=>{
  for(const [opts,code,maxBytes] of [[{status:302,headers:{location:"https://evil.invalid"}},"REMOTE_PROVIDER_UNAVAILABLE"],
    [{status:404},"REMOTE_CONFIG_UNAVAILABLE"],[{headers:{"content-encoding":"gzip"}},"REMOTE_RESPONSE_INVALID"],
    [{data:Buffer.alloc(32)},"REMOTE_TOO_LARGE",16]]){
    await t.test(code,async sub=>{network(sub,opts);await assert.rejects(()=>downloadApproved({url:mnrReferenceUrl(id),kind:"mnr",...(maxBytes?{maxBytes}:{})}),{code});});
  }
});

test("online API requires session and explicit import consent before fetching; text action resolves the same reference",async t=>{
  const {redis,request}=session(t);let downloads=0,workers=0;
  const bytes=Buffer.from("synthetic encrypted profile");
  const options={storeProvider:async()=>redis,vendor:{download:async()=>{
    downloads++;return downloads%2===1?Buffer.from(JSON.stringify(metadata)):bytes;
  }},fetchImpl:async(url,options)=>{
    workers++;assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/file");
    const input=JSON.parse(options.body);assert.equal(input.format,"stp");assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
    return Response.json(result(profile));
  }};
  assert.equal((await externalImportRequest(request({reference,consent:true},null),"mnr",options)).status,401);
  assert.equal((await externalImportRequest(request({reference,consent:false}),"mnr",options)).status,400);
  assert.equal((await externalImportRequest(request({reference:"https://127.0.0.1/",consent:true}),"mnr",options)).status,400);
  assert.equal(downloads,0);assert.equal(workers,0);
  const imported=await externalImportRequest(request({reference,consent:true}),"mnr",options);
  assert.equal(imported.status,200);assert.deepEqual((await imported.json()).structuredJson,profile);
  const text=await decodeRequest(request({text:reference}),"text",options);
  assert.equal(text.status,200);assert.deepEqual((await text.json()).structuredJson,profile);
  assert.equal(downloads,4);assert.equal(workers,2);
  process.env.CLOUD_SERVER_VPN_ENABLED="false";
  assert.equal((await decodeRequest(request({text:reference}),"text",options)).status,503);
  assert.equal(downloads,4);
});

test("MNR full catalog broker forwards fixed source bytes through the authenticated worker",async t=>{
  const {redis,request}=session(t),bytes=Buffer.from("synthetic MNR catalog");
  t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://raw.githubusercontent.com/buttacuore2025/up/refs/heads/main/plusfast");
    assert.equal(options.headers["User-Agent"],"MNR TUNNEL PLUS/3.1");
    const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{
      const res=new EventEmitter();res.statusCode=200;res.headers={};res.resume=()=>{};callback(res);res.emit("data",bytes);res.emit("end");
    });return req;
  });
  const response=await decodeServerVpn(request({id:"mnr-tunnel-plus",consent:true}),{
    storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
      const input=JSON.parse(options.body);assert.equal(input.providerId,"mnr-tunnel-plus");assert.deepEqual(Buffer.from(input.dataBase64,"base64"),bytes);
      return Response.json(result(doc,"vpn_catalog"));
    }});
  assert.equal(response.status,200);assert.deepEqual((await response.json()).structuredJson,doc);
});

test("MNR gateway rejects inconsistent and partial profile or catalog output",async t=>{
  session(t);
  for(const [kind,payload,obj] of [["file",{format:"stp"},profile],["server-vpn",{providerId:"mnr-tunnel-plus"},doc]]){
    for(const bad of [{...result(obj,kind==="file"?"file":"vpn_catalog"),isPartial:true},
      {...result(obj,kind==="file"?"file":"vpn_catalog"),structuredJson:{different:true}}]){
      await assert.rejects(()=>fetchWorker(kind,payload,{workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(bad)}),/INVALID_WORKER_RESULT/);
    }
  }
});
