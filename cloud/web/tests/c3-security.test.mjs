import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { settings } from "../lib/c3-config.mjs";
import { checkIntegrityVerdict, verifyPlayToken } from "../lib/c3-integrity.mjs";
import { createChallenge, issueSession, requireSession, verifySignature } from "../lib/c3-session.mjs";
import { decodeRequest, sessionRequest, challengeRequest, readinessRequest, capabilitiesRequest } from "../lib/c3-gateway.mjs";

class FakeRedis {
  constructor(){this.values=new Map();this.counters=new Map();this.slots=new Map();}
  async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
  async get(k){return this.values.get(k)??null;}
  async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
  async incr(k){const v=(this.counters.get(k)||0)+1;this.counters.set(k,v);return v;}
  async expire(){return 1;}
  async eval(script,{keys,arguments:args}){
    const k=keys[0],map=this.slots.get(k)||new Map();
    for(const [id,time] of map){if(time<=Number(args[2]))map.delete(id);}
    if(map.size>=Number(args[1]))return 0;
    map.set(args[0],Number(args[3]));this.slots.set(k,map);return 1;
  }
  async zRem(k,id){this.slots.get(k)?.delete(id);return 1;}
  async ping(){return "PONG";}
}
const pair=generateKeyPairSync("rsa",{modulusLength:2048});
const account={type:"service_account",client_email:"fake-integration-test@example.invalid",private_key:pair.privateKey.export({type:"pkcs8",format:"pem"})};
const env={
  CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"c".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
  CLOUD_REDIS_URL:"redis://redis:6379",CLOUD_TRUST_PROXY:"true",
  CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify(account),
  WORKER_INTERNAL_URL:"http://decoder-worker:8787",
};
const req=(body,token,ip="203.0.113.20")=>new Request("https://spdecode.example.test/api/v1/decode/file",{
  method:"POST",headers:{"Content-Type":"application/json","X-Real-IP":ip,...(token?{Authorization:"Bearer "+token}:{})},
  body:JSON.stringify(body),
});
test("C3 must fail closed when any required server configuration is missing",()=>{
  assert.equal(settings({}).configured,false);
  assert.equal(settings({...env,CLOUD_WORKER_TOKEN:"short"}).configured,false);
  assert.equal(settings({...env,CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:"invalid"}).configured,false);
  assert.equal(settings({...env,CLOUD_TRUST_PROXY:"false"}).configured,false);
});
Object.assign(process.env,env);
const cfg=settings();
test("C3 is enabled only with all server-side security controls configured",()=>{
  assert.equal(cfg.configured,true);
  assert.equal(cfg.packageName,"com.ghostdeveloper.spdecode");
});
const baseVerdict=(nonce,delta=0)=>({tokenPayloadExternal:{
  requestDetails:{requestPackageName:cfg.packageName,nonce,timestampMillis:String(Date.now()+delta)},
  appIntegrity:{packageName:cfg.packageName,appRecognitionVerdict:"PLAY_RECOGNIZED"},
  deviceIntegrity:{deviceRecognitionVerdict:["MEETS_DEVICE_INTEGRITY"]},
  accountDetails:{appLicensingVerdict:"LICENSED"},
}});
test("Play Integrity rejects wrong nonce, package, stale timestamp, forged app or missing license",()=>{
  const good=baseVerdict("good");
  assert.equal(checkIntegrityVerdict(good,{nonce:"good",packageName:cfg.packageName}),true);
  assert.equal(checkIntegrityVerdict(good,{nonce:"wrong",packageName:cfg.packageName}),false);
  assert.equal(checkIntegrityVerdict(baseVerdict("good",-130000),{nonce:"good",packageName:cfg.packageName}),false);
  assert.equal(checkIntegrityVerdict(good,{nonce:"good",packageName:"com.other.app"}),false);
  assert.equal(checkIntegrityVerdict({...good,tokenPayloadExternal:{...good.tokenPayloadExternal,appIntegrity:{appRecognitionVerdict:"UNRECOGNIZED_VERSION"}}},{nonce:"good",packageName:cfg.packageName}),false);
  assert.equal(checkIntegrityVerdict(good,{nonce:"good",packageName:cfg.packageName,requireStrong:true}),false);
  assert.equal(checkIntegrityVerdict({...good,tokenPayloadExternal:{...good.tokenPayloadExternal,accountDetails:{appLicensingVerdict:"UNLICENSED"}}},{nonce:"good",packageName:cfg.packageName}),false);
});
test("Google Play Integrity fetch uses fixed OAuth and Google API destinations",async()=>{
  let calls=0;
  const fetchImpl=async (url,options)=>{
    calls++;
    if(calls===1){
      assert.equal(url,"https://oauth2.googleapis.com/token");
      assert.match(options.body,/assertion=/);
      return {ok:true,json:async()=>({token_type:"Bearer",access_token:"test-oauth-access"})};
    }
    assert.equal(url,"https://playintegrity.googleapis.com/v1/com.ghostdeveloper.spdecode:decodeIntegrityToken");
    assert.equal(options.headers.Authorization,"Bearer test-oauth-access");
    return {ok:true,json:async()=>baseVerdict("nonce-token")};
  };
  assert.equal(await verifyPlayToken("T".repeat(100),"nonce-token",cfg,{fetchImpl}),true);
  assert.equal(calls,2);
});
async function authorized(redis,ip="203.0.113.20"){
  const challenge=await createChallenge(redis,req({}),);
  // createChallenge requires request and Redis. The explicit IP value is
  // passed on each subsequent request for consistent challenge binding.
  const created=await createChallenge(redis,req({},null,ip));
  const issued=await issueSession(redis,req({},null,ip),{challengeId:created.challengeId,integrityToken:"T".repeat(100)},cfg,async()=>true);
  assert.ok(issued.accessToken,JSON.stringify(issued));
  return {created,issued};
}
test("challenge is single-use; short-lived signed tokens reject tampering and stale clocks",async()=>{
  const redis=new FakeRedis();
  const challenge=await createChallenge(redis,req({}));
  assert.equal(challenge.nonce.length>=40,true);
  const issued=await issueSession(redis,req({}),{challengeId:challenge.challengeId,integrityToken:"x".repeat(100)},cfg,async()=>true);
  assert.equal(issued.tokenType,"Bearer");
  const claims=verifySignature(issued.accessToken,cfg.signingKey);
  assert.ok(claims);
  assert.equal(verifySignature(issued.accessToken+"bad",cfg.signingKey),null);
  assert.equal(verifySignature(issued.accessToken,cfg.signingKey,claims.exp+1),null);
  const second=await issueSession(redis,req({}),{challengeId:challenge.challengeId,integrityToken:"x".repeat(100)},cfg,async()=>true);
  assert.equal(second.error,"EXPIRED_CHALLENGE");
  assert.equal(await requireSession(redis,req({},issued.accessToken),cfg).then(x=>x?.jti),claims.jti);
});
test("private worker remains accessible only after admission; response is not truncated",async()=>{
  const redis=new FakeRedis();
  const {issued}=await authorized(redis);
  let workerCalls=0;
  const source={format:"tls",dataBase64:Buffer.from("synthetic").toString("base64")};
  const fetchImpl=async (url,opts)=>{
    workerCalls++;
    assert.equal(url,"http://decoder-worker:8787/internal/v1/decode/file");
    assert.equal(opts.headers["X-SP-Worker-Token"],cfg.workerToken);
    return {status:200,text:async()=>JSON.stringify({status:"success",rawText:"line one\nline two\n",structuredJson:null,isPartial:false,warnings:[]})};
  };
  const noToken=await decodeRequest(req(source), "file",{storeProvider:async()=>redis,fetchImpl});
  assert.equal(noToken.status,401);
  const ok=await decodeRequest(req(source,issued.accessToken),"file",{storeProvider:async()=>redis,fetchImpl});
  assert.equal(ok.status,200);assert.equal((await ok.json()).rawText,"line one\nline two\n");
  assert.equal(workerCalls,1);
  const invalid=await decodeRequest(req({format:"../tls",dataBase64:"dGVzdA=="},issued.accessToken),"file",{storeProvider:async()=>redis,fetchImpl});
  assert.equal(invalid.status,400);
  assert.equal(workerCalls,1);
});
test("file size, invalid JSON and cross-format credentials fail before the worker",async()=>{
  const redis=new FakeRedis();const {issued}=await authorized(redis,"203.0.113.21");
  const common={storeProvider:async()=>redis,fetchImpl:async()=>{throw Error("worker must not be called");}};
  const bad=await decodeRequest(req({format:"tls",dataBase64:"aGVs bG8="},issued.accessToken,"203.0.113.21"),"file",common);
  assert.equal(bad.status,400);
  const creds=await decodeRequest(req({format:"tls",dataBase64:"YWJj",credentials:{password:"bad"}},issued.accessToken,"203.0.113.21"),"file",common);
  assert.equal(creds.status,400);
  const badtype=new Request("https://spdecode.example.test/api/v1/decode/file",{method:"POST",headers:{Authorization:"Bearer "+issued.accessToken,"Content-Type":"text/plain","X-Real-IP":"203.0.113.21"},body:"x"});
  const type=await decodeRequest(badtype,"file",common);assert.equal(type.status,400);
});
test("C3 challenge and session routes can be exercised with injected verifier; replay denied",async()=>{
  const redis=new FakeRedis();
  const options={storeProvider:async()=>redis};
  const challenge=await challengeRequest(req({}),options);
  assert.equal(challenge.status,201);
  const data=await challenge.json();
  const session=await sessionRequest(req({challengeId:data.challengeId,integrityToken:"T".repeat(100)}),{...options,verifyIntegrity:async()=>true});
  assert.equal(session.status,201);
  const bearer=(await session.json()).accessToken;
  const repeat=await sessionRequest(req({challengeId:data.challengeId,integrityToken:"T".repeat(100)}),{...options,verifyIntegrity:async()=>true});
  assert.equal(repeat.status,401);
  assert.ok(bearer);
});
test("readiness is not a false positive when worker is offline",async()=>{
  const redis=new FakeRedis();
  const notReady=await readinessRequest({storeProvider:async()=>redis,fetchImpl:async()=>({ok:false})});
  assert.equal(notReady.status,503);
  const ready=await readinessRequest({storeProvider:async()=>redis,fetchImpl:async()=>({ok:true})});
  assert.equal(ready.status,200);
});
test("capabilities require live private worker metadata, never invented certification",async()=>{
  const cap=await capabilitiesRequest({fetchImpl:async()=>({ok:true,json:async()=>({
    fileRoutes:Array.from({length:240},(_,i)=>"format"+i),
    exporterCertified:false,textDecodingEnabled:true,nurCatalogEnabled:true,
  })})});
  assert.equal(cap.status,200);
  const data=await cap.json();
  assert.equal(data.enabledFormats.length,240);
  assert.equal(data.fileDecoderCatalog.exporterVersionsCertified,0);
  assert.equal(data.cloudImportsEnabled,false);
});
