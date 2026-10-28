import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {generateKeyPairSync,randomBytes,sign as ecSign,createHash} from "node:crypto";
import {transportRequest} from "../lib/v2-transport.mjs";
import {v2Settings,legacyApiRetired} from "../lib/v2-config.mjs";
import {integrityNonce,proofMessage,verifyProof} from "../lib/v2-proof.mjs";
import {sign,requireSession} from "../lib/c3-session.mjs";
import {checkIntegrityVerdict} from "../lib/c3-integrity.mjs";
import {decodeRequest} from "../lib/c3-gateway.mjs";
import {proxy} from "../proxy.js";
class Redis {
  values=new Map();counts=new Map();
  async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
  async get(k){return this.values.get(k)??null;}
  async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
  async incr(k){const n=(this.counts.get(k)||0)+1;this.counts.set(k,n);return n;}
  async expire(){return 1;} async eval(script,opts){if(script.includes("spdecode:throttle:v1"))return this.incr(opts.keys[0]);return 1;} async zRem(){return 1;}
}
const certificate="a1".repeat(32),rsa=generateKeyPairSync("rsa",{modulusLength:2048});
const env={CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
  CLOUD_REDIS_URL:"redis://redis:6379",CLOUD_TRUST_PROXY:"true",CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify({type:"service_account",client_email:"test@example.invalid",
    private_key:rsa.privateKey.export({format:"pem",type:"pkcs8"})}),CLOUD_PLAY_CERT_SHA256:certificate,
  CLOUD_KEY_ATTESTATION_REQUIRED:"false",CLOUD_ACTION_INTEGRITY_REQUIRED:"false",
  CLOUD_MIN_ANDROID_VERSION_CODE:"33",WORKER_INTERNAL_URL:"http://decoder-worker:8787"};
const pair=()=>generateKeyPairSync("ec",{namedCurve:"prime256v1"});
const encoded=p=>p.publicKey.export({type:"spki",format:"der"}).toString("base64url");
const verdict=nonce=>({tokenPayloadExternal:{
  requestDetails:{nonce,requestPackageName:env.CLOUD_GOOGLE_PLAY_PACKAGE,timestampMillis:String(Date.now())},
  appIntegrity:{appRecognitionVerdict:"PLAY_RECOGNIZED",packageName:env.CLOUD_GOOGLE_PLAY_PACKAGE,
    certificateSha256Digest:[Buffer.from(certificate,"hex").toString("base64url")],versionCode:"33"},
  deviceIntegrity:{deviceAttributes:{sdkVersion:35},recentDeviceActivity:{deviceActivityLevel:"LEVEL_1"},deviceRecognitionVerdict:["MEETS_DEVICE_INTEGRITY","MEETS_STRONG_INTEGRITY"]},
  accountDetails:{appLicensingVerdict:"LICENSED"},
  environmentDetails:{playProtectVerdict:"NO_ISSUES",appAccessRiskVerdict:{appsDetected:["KNOWN_INSTALLED"]}},
}});
function request(op,body,key,bearer="",extra={}) {
  const bytes=typeof body==="string"?body:JSON.stringify(body);
  const timestamp=String(Math.floor(Date.now()/1000)),nonce=randomBytes(24).toString("base64url");
  const proof=ecSign("sha256",Buffer.from(proofMessage(op,"1.1.22",timestamp,nonce,bearer,Buffer.from(bytes))),key.privateKey).toString("base64url");
  return new Request("https://api.example.test/api/v2/transport",{method:"POST",headers:{
    "content-type":"application/json","x-real-ip":"203.0.113.7","x-sp-operation":String(op),
    "x-spdecode-app-version":"1.1.22","x-sp-timestamp":timestamp,"x-sp-nonce":nonce,"x-sp-proof":proof,
    ...(bearer?{authorization:"Bearer "+bearer}:{}),...extra},body:bytes});
}
function fixture(changes={}) {
  const redis=new Redis(),key=pair(),options={env:{...env,...changes},storeProvider:async()=>redis};
  return {redis,key,options,call:(op,body,token="",headers={})=>transportRequest(request(op,body,key,token,headers),options)};
}
async function authorize(f) {
  const challenge=await (await f.call(1,{publicKey:encoded(f.key)})).json();
  const nonce=integrityNonce(challenge.nonce,challenge.challengeId,encoded(f.key));
  f.options.decodeIntegrity=async()=>verdict(nonce);
  const result=await f.call(2,{challengeId:challenge.challengeId,integrityToken:"T".repeat(100)});
  assert.equal(result.status,201);
  return {token:(await result.json()).accessToken,challenge,nonce};
}
test("V2 fails closed on missing signer, invalid version/epoch and beta-only Google setup",()=>{
  assert(v2Settings(env).configured);
  for(const change of [{CLOUD_PLAY_CERT_SHA256:""},{CLOUD_PLAY_CERT_SHA256:"bad"},{CLOUD_MIN_ANDROID_VERSION_CODE:"32"},
    {CLOUD_MIN_ANDROID_VERSION_CODE:"NaN"},{CLOUD_V2_SESSION_EPOCH:"x\n"},
    {CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:"",CLOUD_BETA_ADMISSION_ENABLED:"true"}])
    assert.equal(v2Settings({...env,...change}).configured,false);
  assert(v2Settings({...env,CLOUD_REQUIRE_LICENSED:"false"}).requireLicensed);
  assert(v2Settings(env).requireStrong);
});
test("shared Android/server vector signs exact Unicode bytes using DER ECDSA",()=>{
  const v=JSON.parse(readFileSync(new URL("../../../android/app/src/androidTest/assets/v2-proof-vector.json",import.meta.url)));
  const bytes=Buffer.from(v.body),message=proofMessage(v.operation,v.version,v.timestamp,v.nonce,v.bearer,bytes);
  assert.equal(createHash("sha256").update(message).digest("hex"),v.messageSha256);
  const req=new Request("https://example.test/api/v2/transport",{headers:{"x-sp-timestamp":v.timestamp,
    "x-sp-nonce":v.nonce,"x-sp-proof":v.signature,"x-spdecode-app-version":v.version}});
  assert.equal(verifyProof(req,v.operation,bytes,v.bearer,v.publicKey,Number(v.timestamp)*1000),v.nonce);
});
test("V1 routes remain available; explicit retirement closes them without closing probes",()=>{
  for(const path of ["/api/v1","/api/v1/session","/api/v1/session/qa","/api/v1/decode/file",
    "/api/v1/server-vpn/catalog","/api/v1/unknown-alias"]){
    assert.equal(legacyApiRetired(path,{}),false);
    assert(legacyApiRetired(path,{CLOUD_LEGACY_API_ENABLED:"false"}));
    assert.equal(legacyApiRetired(path,{CLOUD_LEGACY_API_ENABLED:"true"}),false);
  }
  for(const path of ["/api/v1/health","/api/v1/ready","/api/admin/login","/api/v2/transport"])
    assert.equal(legacyApiRetired(path,{}),false);
});
test("attestation enforces package, signer, version, licensing, device, optional risk and freshness",()=>{
  const cfg={...v2Settings(env),nonce:"nonce"};
  assert(checkIntegrityVerdict(verdict("nonce"),cfg));
  for(const mutate of [
    v=>v.requestDetails.nonce="other",v=>v.requestDetails.requestPackageName="com.other",
    v=>v.requestDetails.timestampMillis=String(Date.now()+6000),
    v=>v.requestDetails.timestampMillis=String(Date.now()-121000),
    v=>v.appIntegrity.packageName="com.other",v=>v.appIntegrity.appRecognitionVerdict="UNRECOGNIZED_VERSION",
    v=>v.appIntegrity.certificateSha256Digest=[],v=>v.appIntegrity.certificateSha256Digest=["b".repeat(43)],
    v=>v.appIntegrity.versionCode="32",v=>delete v.appIntegrity.versionCode,v=>v.appIntegrity.versionCode="33junk",
    v=>v.accountDetails.appLicensingVerdict="UNLICENSED",
    v=>v.deviceIntegrity.deviceRecognitionVerdict=["MEETS_DEVICE_INTEGRITY"],
    v=>v.deviceIntegrity.deviceAttributes.sdkVersion=32,
    v=>v.deviceIntegrity.recentDeviceActivity.deviceActivityLevel="LEVEL_4"]){
    const value=verdict("nonce");mutate(value.tokenPayloadExternal);assert.equal(checkIntegrityVerdict(value,cfg),false);
  }
  for(const field of ["requireAccessRisk","requirePlayProtect"]){
    const value=verdict("nonce");delete value.tokenPayloadExternal.environmentDetails;
    assert.equal(checkIntegrityVerdict(value,{...cfg,[field]:true}),false);
  }
  const value=verdict("nonce");value.tokenPayloadExternal.environmentDetails.appAccessRiskVerdict.appsDetected=["UNKNOWN_CONTROLLING"];
  assert.equal(checkIntegrityVerdict(value,{...cfg,requireAccessRisk:true}),false);
});
test("challenge binds key and IP; invalid attestation consumes it and replay fails",async()=>{
  const f=fixture(),{challenge}=await authorize(f);
  assert.equal((await f.call(2,{challengeId:challenge.challengeId,integrityToken:"T".repeat(100)})).status,401);
  for(const change of ["key","ip","token"]){
    const g=fixture(),c=await(await g.call(1,{publicKey:encoded(g.key)})).json();
    g.options.decodeIntegrity=async()=>verdict(change==="token"?c.nonce:integrityNonce(c.nonce,c.challengeId,encoded(g.key)));
    const req=request(2,{challengeId:c.challengeId,integrityToken:"T".repeat(100)},change==="key"?pair():g.key,"",
      change==="ip"?{"x-real-ip":"203.0.113.8"}:{});
    assert.equal((await transportRequest(req,g.options)).status,403);
    assert.equal((await g.call(2,{challengeId:c.challengeId,integrityToken:"T".repeat(100)})).status,401);
  }
});
test("valid proof reaches handler; concurrent replay and changed operation fail",async()=>{
  const f=fixture(),{token}=await authorize(f);let calls=0;
  f.options.dispatch=async(op,req)=>{calls++;assert.equal(op,5);assert.deepEqual(await req.json(),{format:"hc",dataBase64:"YWJj"});
    assert.equal((await requireSession(f.redis,req,v2Settings(env))).aud,"spdecode-android-v2");return Response.json({ok:true});};
  const req=request(5,{format:"hc",dataBase64:"YWJj"},f.key,token);
  const statuses=await Promise.all([req.clone(),req.clone()].map(r=>transportRequest(r,f.options).then(x=>x.status)));
  assert.deepEqual(statuses.sort(),[200,401]);assert.equal(calls,1);
  const changed=request(5,{},f.key,token);changed.headers.set("x-sp-operation","6");
  assert.equal((await transportRequest(changed,f.options)).status,401);
});
test("stolen token without key, body/version tampering, stale proofs and invalid DER fail",async()=>{
  const f=fixture(),{token}=await authorize(f);f.options.dispatch=()=>{throw Error("unexpected handler");};
  assert.equal((await transportRequest(request(10,{},pair(),token),f.options)).status,401);
  for(const [name,value] of [["x-sp-timestamp",String(Math.floor(Date.now()/1000)-40)],
    ["x-sp-timestamp",String(Math.floor(Date.now()/1000)+40)],["x-spdecode-app-version","1.1.23"],
    ["x-sp-proof","A".repeat(96)],["x-sp-nonce","A".repeat(32)]])
    assert.equal((await f.call(10,{},token,{[name]:value})).status,401);
  const valid=request(10,'{"knownVersion":1}',f.key,token);
  assert.equal((await transportRequest(new Request(valid.url,{method:"POST",headers:valid.headers,body:'{"knownVersion":2}'}),f.options)).status,401);
  assert.equal((await f.call(10,{},"",{"x-sp-internal-verified":"true"})).status,401);
});
test("V1/QA tokens cannot downgrade V2; epoch, release, signer and Redis revocation are live",async()=>{
  const f=fixture(),{token}=await authorize(f);f.options.dispatch=async()=>Response.json({ok:true});
  const now=Math.floor(Date.now()/1000);
  const legacy=sign({iss:"spdecode-cloud",aud:"spdecode-android-v1",scope:"decode",iat:now,exp:now+300,
    jti:"00000000-0000-0000-0000-000000000000",channel:"qa"},env.CLOUD_SESSION_SIGNING_KEY);
  assert.equal((await f.call(5,{},legacy)).status,401);
  for(const change of [{CLOUD_V2_SESSION_EPOCH:"2"},{CLOUD_MIN_ANDROID_VERSION_CODE:"34"},{CLOUD_PLAY_CERT_SHA256:"b2".repeat(32)}]){
    f.options.env={...env,...change};assert.equal((await f.call(10,{},token)).status,401);
  }
  f.options.env=env;
  for(const key of f.redis.values.keys())if(key.startsWith("spc2:session:"))f.redis.values.delete(key);
  assert.equal((await f.call(10,{},token)).status,401);
});
test("bootstrap validates key, proof, fixed operation, encoding and query before dispatch",async()=>{
  const f=fixture();
  for(const op of ["3","17","01","/api/v1/decode/file"])assert.equal((await f.call(op,{})).status,400);
  assert.equal((await f.call(1,{publicKey:encoded(pair())})).status,400);
  assert.equal((await f.call(1,{publicKey:encoded(f.key),extra:true})).status,400);
  assert.equal((await f.call(1,{publicKey:encoded(f.key)},"",{"content-encoding":"gzip"})).status,400);
  const q=request(1,{publicKey:encoded(f.key)},f.key);
  assert.equal((await transportRequest(new Request(q.url+"?route=decode/file",q),f.options)).status,400);
});
test("oversized bootstrap bodies, Google outage and Redis outage fail closed",async()=>{
  const f=fixture();assert.equal((await f.call(1,'{"publicKey":"'+"x".repeat(5000)+'"}')).status,413);
  const {challenge}=await authorize(f),c=await(await f.call(1,{publicKey:encoded(f.key)})).json();
  f.options.decodeIntegrity=async()=>{throw Error("Google offline");};
  assert.equal((await f.call(2,{challengeId:c.challengeId,integrityToken:"T".repeat(100)})).status,503);
  f.options.storeProvider=async()=>{throw Error("Redis offline");};
  assert.equal((await f.call(2,{challengeId:challenge.challengeId,integrityToken:"T".repeat(100)})).status,503);
});
test("metadata and expensive operation rate budgets remain independent",async()=>{
  const f=fixture(),{token}=await authorize(f);f.options.dispatch=async()=>Response.json({ok:true});
  for(let i=0;i<11;i++)assert.equal((await f.call(11,{id:"x"},token)).status,200);
  for(let i=0;i<10;i++)assert.equal((await f.call(i%2?5:6,{},token)).status,200);
  assert.equal((await f.call(12,{},token)).status,429);
});
test("V2 reaches real decoder only after proof and preserves existing worker validation",async()=>{
  Object.assign(process.env,env);const f=fixture(),{token}=await authorize(f);let calls=0;
  f.options.dispatch=(op,req)=>decodeRequest(req,"file",{storeProvider:async()=>f.redis,
    fetchImpl:async()=>{calls++;return Response.json({status:"success",rawText:'{"ok":true}',isPartial:false});}});
  const response=await f.call(5,{format:"hc",dataBase64:"YWJj"},token);
  assert.equal(response.status,200);assert.equal(calls,1);assert.equal((await response.json()).rawText,'{"ok":true}');
});

