import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import dns from "node:dns/promises";
import https from "node:https";
import {createHmac,randomUUID} from "node:crypto";
import {CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {fetchWorker} from "../lib/c3-gateway.mjs";
import {decodeServerVpn} from "../lib/server-vpn-gateway.mjs";
import {buildGenerateBody,inventOpentunnelCredentials,isValidOpentunnelDeviceId,
  markOpentunnelCredentialsMissing,mergeOpentunnelGenerateResult,
  packOpentunnelCatalog} from "../lib/opentunnel-credentials.mjs";

const DEVICE_ID="4ddb753a-5cbf-3ef6-aeff-ef620702dadd";
const PUBLIC_DOC={status:200,count:2,servers:[
  {hostname:"ssh-de-1.optnl.com",city:"Berlin",country:"Germany",countryCode:"DE",dnstt:"00",premium:false,serverName:"DE 1",status:true},
  {hostname:"ssh-us-1.optnl.com",city:"New York",country:"United States",countryCode:"US",dnstt:"00",premium:false,serverName:"US 1",status:true},
]};

test("invented pair follows Pedro's exact format, suffixes always differ",()=>{
  const seen=new Set();
  for(let i=0;i<50;i++){
    const {username,password}=inventOpentunnelCredentials();
    assert.match(username,/^spdecode-[a-z0-9]{6}$/);
    assert.match(password,/^spdecode-[a-z0-9]{6}$/);
    assert.equal(username.length,15);
    assert.equal(password.length,15);
    assert.notEqual(username.slice(9),password.slice(9));
    assert(!seen.has(username+password));
    seen.add(username+password);
  }
});

test("deviceId validation accepts only the canonical lowercase UUID the app sends",()=>{
  assert.equal(isValidOpentunnelDeviceId(DEVICE_ID),true);
  assert.equal(isValidOpentunnelDeviceId("4DDB753A-5CBF-3EF6-AEFF-EF620702DADD"),false);
  assert.equal(isValidOpentunnelDeviceId("4ddb753a5cbf3ef6aeffef620702dadd"),false);
  assert.equal(isValidOpentunnelDeviceId("not-a-uuid"),false);
  assert.equal(isValidOpentunnelDeviceId(""),false);
  assert.equal(isValidOpentunnelDeviceId(null),false);
  assert.equal(isValidOpentunnelDeviceId(123),false);
});

test("generate body matches the official app's exact shape and key order",()=>{
  const body=buildGenerateBody(DEVICE_ID,{username:"spdecode-abc123",password:"spdecode-xyz789"});
  assert.deepEqual(Object.keys(body),["action","username","password","client","device_id"]);
  assert.deepEqual(body,{action:"generate",username:"spdecode-abc123",password:"spdecode-xyz789",
    client:"OpenTunnel_1.1.1",device_id:DEVICE_ID});
  assert.throws(()=>buildGenerateBody("bad",{username:"spdecode-abc123",password:"spdecode-xyz789"}),{code:"INVALID_REQUEST"});
});

test("merge uses the server-echoed username and the invented password per server",()=>{
  const creds={username:"spdecode-aaaaaa",password:"spdecode-bbbbbb"};
  const response=JSON.stringify({status:200,count:2,requests:PUBLIC_DOC.servers.map(s=>
    ({hostname:s.hostname,result:{},username:creds.username})),servers:PUBLIC_DOC.servers});
  const merged=mergeOpentunnelGenerateResult(structuredClone(PUBLIC_DOC),response,creds);
  assert.equal(merged.count,2);
  for(const server of merged.servers){
    assert.equal(server.sshUser,creds.username);
    assert.equal(server.sshPass,creds.password);
    assert.equal(server.credentialsMissing,undefined);
  }
  // A server-returned username wins: it is what the provider registered.
  const other=JSON.stringify({status:200,count:2,requests:[
    {hostname:"ssh-de-1.optnl.com",result:{},username:"spdecode-returned"},
    {hostname:"ssh-us-1.optnl.com",result:{},username:creds.username}]});
  const merged2=mergeOpentunnelGenerateResult(structuredClone(PUBLIC_DOC),other,creds);
  assert.equal(merged2.servers[0].sshUser,"spdecode-returned");
  assert.equal(merged2.servers[0].sshPass,creds.password);
});

test("merge marks servers without a generate entry instead of failing the catalog",()=>{
  const creds={username:"spdecode-aaaaaa",password:"spdecode-bbbbbb"};
  const partial=JSON.stringify({status:200,count:2,requests:[
    {hostname:"ssh-de-1.optnl.com",result:{},username:creds.username}]});
  const merged=mergeOpentunnelGenerateResult(structuredClone(PUBLIC_DOC),partial,creds);
  assert.equal(merged.servers[0].sshUser,creds.username);
  assert.equal(merged.servers[1].credentialsMissing,true);
  assert.equal(merged.servers[1].sshUser,undefined);
  // A malformed generate response degrades every server the same way.
  const garbage=mergeOpentunnelGenerateResult(structuredClone(PUBLIC_DOC),"not json",creds);
  assert.ok(garbage.servers.every(s=>s.credentialsMissing===true));
  assert.throws(()=>mergeOpentunnelGenerateResult(null,"{}",creds),{code:"REMOTE_RESPONSE_INVALID"});
  assert.deepEqual(markOpentunnelCredentialsMissing(structuredClone(PUBLIC_DOC)).servers
    .map(s=>s.credentialsMissing),[true,true]);
});

test("pack preserves the public document and rejects count/status drift",()=>{
  const bytes=packOpentunnelCatalog(structuredClone(PUBLIC_DOC));
  assert.deepEqual(JSON.parse(bytes.toString("utf8")),PUBLIC_DOC);
  assert.throws(()=>packOpentunnelCatalog({...PUBLIC_DOC,count:3}),{code:"REMOTE_RESPONSE_INVALID"});
  assert.throws(()=>packOpentunnelCatalog({...PUBLIC_DOC,status:500}),{code:"REMOTE_RESPONSE_INVALID"});
  assert.throws(()=>packOpentunnelCatalog(null),{code:"REMOTE_RESPONSE_INVALID"});
});

test("gateway accepts an enriched OpenTunnel document with per-user credentials",async t=>{
  const before=process.env.WORKER_INTERNAL_URL;process.env.WORKER_INTERNAL_URL="http://decoder-worker:8787";
  t.after(()=>{if(before===undefined)delete process.env.WORKER_INTERNAL_URL;else process.env.WORKER_INTERNAL_URL=before;});
  const doc={...PUBLIC_DOC,servers:PUBLIC_DOC.servers.map(s=>({...s,sshUser:"spdecode-aaaaaa",sshPass:"spdecode-bbbbbb"}))};
  const result={apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"opentunnel-ssh",
    rawText:JSON.stringify(doc),structuredJson:doc,isPartial:false,warnings:[],exporterCertified:false};
  const call=r=>fetchWorker("server-vpn",{providerId:"opentunnel-ssh"},
    {workerToken:"w".repeat(48)},{fetchImpl:async()=>Response.json(r)});
  assert.deepEqual((await (await call(result)).json()).structuredJson,doc);
  await assert.rejects(()=>call({...result,isPartial:true}),/INVALID_WORKER_RESULT/);
});

function mockProviderNetwork(t,{postStatus=200,postBody=null}={}){
  const prior=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=prior;});
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"api.roosterkid.com");return [{address:"93.184.216.34",family:4}];
  });
  const calls=[];
  t.mock.method(https,"request",(url,options,callback)=>{
    assert.equal(url.href,"https://api.roosterkid.com/api/opentunnel/servers/");
    assert.equal(options.headers["User-Agent"],"SP-DECODE/1.0");
    assert.equal(options.rejectUnauthorized,true);
    assert.equal(options.minVersion,"TLSv1.2");
    const request=new EventEmitter();request.destroy=()=>{};
    request.end=body=>{
      calls.push({method:options.method,headers:options.headers,body:body?.toString("utf8")??null});
      queueMicrotask(()=>{
        const response=new EventEmitter();response.resume=()=>{};
        if(options.method==="GET"){
          response.statusCode=200;response.headers={};callback(response);
          response.emit("data",Buffer.from(JSON.stringify(PUBLIC_DOC)));response.emit("end");
          return;
        }
        // POST generate: echo the invented username the broker sent.
        assert.equal(options.method,"POST");
        assert.equal(options.headers["Content-Type"],"application/json; charset=UTF-8");
        const sent=JSON.parse(calls.at(-1).body);
        assert.equal(sent.action,"generate");
        assert.equal(sent.client,"OpenTunnel_1.1.1");
        response.statusCode=postStatus;response.headers={};callback(response);
        if(postStatus===200){
          const payload=postBody??{status:200,count:2,
            requests:PUBLIC_DOC.servers.map(s=>({hostname:s.hostname,result:{},username:sent.username})),
            servers:PUBLIC_DOC.servers};
          response.emit("data",Buffer.from(JSON.stringify(payload)));
        }
        response.emit("end");
      });
    };
    return request;
  });
  return calls;
}

test("without a deviceId the broker still makes a single fixed GET and nothing else",async t=>{
  const calls=mockProviderNetwork(t);
  assert.equal((await downloadVpnCatalog("opentunnel-ssh")).toString(),JSON.stringify(PUBLIC_DOC));
  assert.equal(calls.length,1);
  assert.equal(calls[0].method,"GET");
  assert.equal(calls[0].body,null);
});

test("with a deviceId the broker makes one GET plus exactly one generate POST",async t=>{
  const calls=mockProviderNetwork(t);
  const bytes=await downloadVpnCatalog("opentunnel-ssh","servers",{deviceId:DEVICE_ID});
  const doc=JSON.parse(bytes.toString("utf8"));
  assert.equal(calls.length,2);
  assert.equal(calls[0].method,"GET");
  assert.equal(calls[1].method,"POST");
  const sent=JSON.parse(calls[1].body);
  assert.equal(sent.device_id,DEVICE_ID);
  assert.match(sent.username,/^spdecode-[a-z0-9]{6}$/);
  assert.match(sent.password,/^spdecode-[a-z0-9]{6}$/);
  assert.notEqual(sent.username.slice(9),sent.password.slice(9));
  assert.equal(doc.count,2);
  for(const server of doc.servers){
    assert.equal(server.sshUser,sent.username);
    assert.equal(server.sshPass,sent.password);
  }
});

test("a failed generate degrades to the public list with every server marked",async t=>{
  const calls=mockProviderNetwork(t,{postStatus:500});
  const doc=JSON.parse((await downloadVpnCatalog("opentunnel-ssh","servers",{deviceId:DEVICE_ID})).toString("utf8"));
  assert.equal(calls.length,2);
  assert.deepEqual(doc.servers.map(s=>s.credentialsMissing),[true,true]);
  assert.equal(doc.servers[0].sshUser,undefined);
  await assert.rejects(()=>downloadVpnCatalog("opentunnel-ssh","servers",{deviceId:"bad"}),{code:"INVALID_REQUEST"});
});

function sessionEnv(t){
  const env={CLOUD_API_ENABLED:"true",CLOUD_SERVER_VPN_ENABLED:"true",CLOUD_BETA_ADMISSION_ENABLED:"true",
    CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
    CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",CLOUD_REDIS_URL:"redis://redis:6379",
    CLOUD_TRUST_PROXY:"true",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
  for(const [key,value] of Object.entries(env)){
    const prior=process.env[key];process.env[key]=value;
    t.after(()=>{if(prior===undefined)delete process.env[key];else process.env[key]=prior;});
  }
  return env;
}

function signedRequest(env,body){
  const now=Math.floor(Date.now()/1000),jti=randomUUID();
  const signed=Buffer.from(JSON.stringify({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,jti})).toString("base64url");
  const token=signed+"."+createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY).update(signed).digest("base64url");
  const redis={get:async key=>key==="spc3:session:"+jti?"1":null,incr:async()=>1,
    expire:async()=>1,eval:async()=>1,zRem:async()=>1};
  return {redis,request:new Request("https://api.example.test/api/v1/server-vpn/decode",{
    method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+token},
    body:JSON.stringify(body)})};
}

test("decodeServerVpn forwards the deviceId and serves the enriched catalog",async t=>{
  const env=sessionEnv(t);
  const calls=mockProviderNetwork(t);
  const {redis,request}=signedRequest(env,{id:"opentunnel-ssh",consent:true,deviceId:DEVICE_ID});
  let workerCalls=0;
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    workerCalls++;
    const input=JSON.parse(options.body);
    assert.equal(input.providerId,"opentunnel-ssh");
    const doc=JSON.parse(Buffer.from(input.dataBase64,"base64").toString("utf8"));
    for(const server of doc.servers){
      assert.match(server.sshUser,/^spdecode-[a-z0-9]{6}$/);
      assert.match(server.sshPass,/^spdecode-[a-z0-9]{6}$/);
    }
    return Response.json({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"opentunnel-ssh",
      structuredJson:doc,rawText:JSON.stringify(doc),isPartial:false,warnings:[],exporterCertified:false});
  }});
  assert.equal(calls.length,2);
  assert.equal(workerCalls,1);
  assert.equal(response.status,200);
  const out=await response.json();
  assert.equal(out.structuredJson.servers[0].sshUser,out.structuredJson.servers[1].sshUser);
  assert.ok(out.structuredJson.servers.every(s=>s.sshUser&&s.sshPass));
});

test("decodeServerVpn rejects a malformed deviceId and a deviceId on other providers",async t=>{
  const env=sessionEnv(t);
  mockProviderNetwork(t);
  for(const body of [
    {id:"opentunnel-ssh",consent:true,deviceId:"not-a-uuid"},
    {id:"opentunnel-ssh",consent:true,deviceId:DEVICE_ID,extra:true},
    {id:"md-proxy-vpn",consent:true,deviceId:DEVICE_ID},
  ]){
    const {redis,request}=signedRequest(env,body);
    const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async()=>Response.json({})});
    assert.equal(response.status,400);
    assert.equal((await response.json()).error.code,"INVALID_REQUEST");
  }
});

test("decodeServerVpn without a deviceId still serves the public list",async t=>{
  const env=sessionEnv(t);
  const calls=mockProviderNetwork(t);
  const {redis,request}=signedRequest(env,{id:"opentunnel-ssh",consent:true});
  const response=await decodeServerVpn(request,{storeProvider:async()=>redis,fetchImpl:async(url,options)=>{
    const input=JSON.parse(options.body);
    const doc=JSON.parse(Buffer.from(input.dataBase64,"base64").toString("utf8"));
    assert.deepEqual(doc,PUBLIC_DOC);
    return Response.json({apiVersion:"v1",status:"success",kind:"vpn_catalog",providerId:"opentunnel-ssh",
      structuredJson:doc,rawText:JSON.stringify(doc),isPartial:false,
      warnings:["El listado público de OpenTunnel contiene hosts SSH; el usuario y la contraseña se generan por cuenta en la aplicación oficial."],exporterCertified:false});
  }});
  assert.equal(calls.length,1);
  assert.equal(response.status,200);
  assert.equal((await response.json()).structuredJson.servers[0].sshUser,undefined);
});

test("catalog version marks the variant B contract",()=>{
  // 91 was the OpenTunnel variant B contract; 92 adds the GCP VPN cloud
  // catalog (gcp-vpn) without changing variant B.
  assert.equal(CATALOG_VERSION,92);
});
