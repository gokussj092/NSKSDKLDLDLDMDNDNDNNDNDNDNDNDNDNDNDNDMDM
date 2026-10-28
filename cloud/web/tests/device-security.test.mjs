import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomBytes,sign as ecSign} from "node:crypto";
import {transportRequest} from "../lib/v2-transport.mjs";
import {v2Settings} from "../lib/v2-config.mjs";
import {proofMessage,integrityNonce,sha256} from "../lib/v2-proof.mjs";
import {attestationChallenge,keyId,verifyHardware} from "../lib/device-security.mjs";
import {requireSession} from "../lib/c3-session.mjs";

class Redis {
  values=new Map();counts=new Map();
  async get(k){return this.values.get(k)??null;}
  async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
  async getDel(k){const v=await this.get(k);this.values.delete(k);return v;}
  async eval(script,{keys}) {assert(script.includes("spdecode:throttle:v1"));
    const n=(this.counts.get(keys[0])||0)+1;this.counts.set(keys[0],n);return n;}
}
const encode=p=>p.publicKey.export({type:"spki",format:"der"}).toString("base64url");
const pair=()=>generateKeyPairSync("ec",{namedCurve:"prime256v1"});
const signer="a1".repeat(32);
const env={CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"w".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
  CLOUD_REDIS_URL:"redis://redis:6379",CLOUD_TRUST_PROXY:"true",CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:JSON.stringify({type:"service_account",client_email:"audit@example.invalid",private_key:"-----BEGIN PRIVATE KEY----- synthetic"}),
  CLOUD_PLAY_CERT_SHA256:signer,CLOUD_KEY_ATTESTATION_TOKEN:"k".repeat(48),CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER:"123456789012"};
function verdict(binding,standard=false) {return {tokenPayloadExternal:{
  requestDetails:{[standard?"requestHash":"nonce"]:binding,requestPackageName:env.CLOUD_GOOGLE_PLAY_PACKAGE,timestampMillis:String(Date.now())},
  appIntegrity:{appRecognitionVerdict:"PLAY_RECOGNIZED",packageName:env.CLOUD_GOOGLE_PLAY_PACKAGE,
    certificateSha256Digest:[Buffer.from(signer,"hex").toString("base64url")],versionCode:"34"},
  deviceIntegrity:{deviceRecognitionVerdict:["MEETS_DEVICE_INTEGRITY","MEETS_STRONG_INTEGRITY"],
    deviceAttributes:{sdkVersion:35},recentDeviceActivity:{deviceActivityLevel:"LEVEL_1"}},
  accountDetails:{appLicensingVerdict:"LICENSED"}}};}
function req(op,body,key,bearer="",headers={},path="/api/v2/transport") {
  const bytes=Buffer.from(JSON.stringify(body)),ts=String(Math.floor(Date.now()/1000)),nonce=randomBytes(24).toString("base64url");
  const proof=ecSign("sha256",Buffer.from(proofMessage(op,"1.1.23",ts,nonce,bearer,bytes)),key.privateKey).toString("base64url");
  return new Request("https://audit.invalid"+path,{method:"POST",headers:{"content-type":"application/json",
    "x-real-ip":"192.0.2.12","x-sp-operation":String(op),"x-spdecode-app-version":"1.1.23",
    "x-sp-timestamp":ts,"x-sp-nonce":nonce,"x-sp-proof":proof,...(bearer?{authorization:"Bearer "+bearer}:{}),...headers},body:bytes});
}
function fixture(changes={}) {const redis=new Redis(),bootstrap=pair(),key=pair(),options={env:{...env,...changes},storeProvider:async()=>redis,
  dispatch:async()=>Response.json({ok:true})};return {redis,bootstrap,key,options,
    call:(op,body,bearer="",headers={})=>transportRequest(req(op,body,key,bearer,headers),options)};}
async function enroll(f,{hardware=true}={}) {
  const r=await transportRequest(req(1,{publicKey:encode(f.bootstrap)},f.bootstrap),f.options);
  assert.equal(r.status,201);const c=await r.json();assert.equal(c.keyAttestationRequired,true);
  f.options.decodeIntegrity=async()=>verdict(integrityNonce(c.nonce,c.challengeId,encode(f.key)));
  f.options.verifyHardware=async(chain,challenge,key,cfg)=>{
    assert.equal(challenge,attestationChallenge(c.nonce,c.challengeId,encode(f.bootstrap)));
    assert.equal(key,encode(f.key));assert.equal(cfg.requireHardware,true);
    return hardware?{valid:true,publicKey:key,level:"tee"}:null;
  };
  const result=await f.call(2,{challengeId:c.challengeId,integrityToken:"T".repeat(100),
    publicKey:encode(f.key),certificateChain:["YWJj","YWJj"]});
  return result;
}
test("advanced policy fails closed without verifier credentials or Play project; staging is explicit",()=>{
  assert(v2Settings(env).configured);
  assert.equal(v2Settings({...env,CLOUD_KEY_ATTESTATION_TOKEN:""}).configured,false);
  assert.equal(v2Settings({...env,CLOUD_GOOGLE_CLOUD_PROJECT_NUMBER:""}).configured,false);
  assert.equal(v2Settings({...env,CLOUD_KEY_ATTESTATION_LEVEL:"software"}).configured,false);
  assert.equal(v2Settings({...env,CLOUD_INTEGRITY_MAX_RECENT_ACTIVITY:"NaN"}).configured,false);
});
test("Google approval alone cannot enroll an unverified software key",async()=>{
  const f=fixture();assert.equal((await enroll(f,{hardware:false})).status,403);
  assert.equal(await f.redis.get("spsec:key:"+keyId(encode(f.key))),null);
});
test("hardware admission binds a newly attested key and supports immediate per-key revocation",async()=>{
  const f=fixture({CLOUD_ACTION_INTEGRITY_REQUIRED:"false"}),res=await enroll(f);assert.equal(res.status,201);
  const token=(await res.json()).accessToken;
  assert.equal((await f.call(10,{},token)).status,200);
  assert.equal((await transportRequest(req(10,{},f.bootstrap,token),f.options)).status,401);
  await f.redis.set("spsec:revoked:"+keyId(encode(f.key)),"1");
  assert.equal((await f.call(10,{},token)).status,401);
});
test("sensitive action needs fresh Google content binding, consumed once",async()=>{
  const f=fixture(),session=await enroll(f);const token=(await session.json()).accessToken,body={format:"hc",dataBase64:"YWJj"};
  assert.equal((await f.call(5,body,token)).status,403);
  const challenge=await(await f.call(16,{operation:5,bodySha256:sha256(JSON.stringify(body))},token)).json();
  f.options.decodeIntegrity=async()=>verdict(challenge.requestHash,true);
  const headers={"x-sp-action-challenge":challenge.challengeId,"x-sp-action-integrity":"G".repeat(100)};
  assert.equal((await f.call(5,body,token,headers)).status,200);
  assert.equal((await f.call(5,body,token,headers)).status,403);
});
test("action attestation for another body or operation cannot authorize work",async()=>{
  const f=fixture(),token=(await(await enroll(f)).json()).accessToken,body={text:"hello"};
  const challenge=await(await f.call(16,{operation:6,bodySha256:sha256(JSON.stringify(body))},token)).json();
  f.options.decodeIntegrity=async()=>{throw Error("Google must not be called for mismatched content");};
  assert.equal((await f.call(6,{text:"changed"},token,{"x-sp-action-challenge":challenge.challengeId,"x-sp-action-integrity":"G".repeat(100)})).status,403);
});
test("V1 can accept bound V2 sessions; legacy panel admission cannot forge bound claims",async()=>{
  const f=fixture({CLOUD_ACTION_INTEGRITY_REQUIRED:"false"}),token=(await(await enroll(f)).json()).accessToken;
  const old={...process.env};Object.assign(process.env,f.options.env);
  try {
    const request=req(10,{},f.key,token,{},"/api/v1/server-vpn/catalog");
    assert.equal((await requireSession(f.redis,request,v2Settings(f.options.env))).hardware,true);
    const wrong=req(10,{},f.bootstrap,token,{},"/api/v1/server-vpn/catalog");
    assert.equal(await requireSession(f.redis,wrong,v2Settings(f.options.env)),null);
  } finally {for(const k of Object.keys(process.env))if(!(k in old))delete process.env[k];Object.assign(process.env,old);}
});
test("private verifier replies cannot substitute a different public key",async()=>{
  const f=fixture(),cfg=v2Settings(f.options.env);
  assert.equal(await verifyHardware(["YWJj","YWJj"],"x".repeat(43),encode(f.key),cfg,
    {fetchImpl:async()=>Response.json({valid:true,publicKey:encode(f.bootstrap),level:"tee"})}),null);
});
