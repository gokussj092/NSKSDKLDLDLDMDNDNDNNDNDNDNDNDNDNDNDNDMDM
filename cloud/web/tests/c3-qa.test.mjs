import assert from "node:assert/strict";
import {test} from "node:test";
import {createHmac} from "node:crypto";
import {settings} from "../lib/c3-config.mjs";
import {createChallenge,requireSession} from "../lib/c3-session.mjs";
import {qaSessionRequest} from "../lib/c3-gateway.mjs";

class RedisFake {
  constructor(){this.kv=new Map();this.count=new Map();}
  async get(k){return this.kv.get(k)??null;}
  async set(k,v,opts={}){if(opts.NX&&this.kv.has(k))return null;this.kv.set(k,v);return "OK";}
  async getDel(k){const v=await this.get(k);this.kv.delete(k);return v;}
  async eval(script,opts){if(script.includes("spdecode:throttle:v1"))return this.incr(opts.keys[0]);throw Error("Unsupported Lua");}
  async incr(k){const v=(this.count.get(k)||0)+1;this.count.set(k,v);return v;}
  async expire(){return 1;}
  async ping(){return "PONG";}
}
const env={
  CLOUD_API_ENABLED:"true",CLOUD_QA_ENABLED:"true",
  CLOUD_QA_EXPIRES_AT:String(Math.floor(Date.now()/1000)+3600),
  CLOUD_WORKER_TOKEN:"c".repeat(48),CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),
  CLOUD_REDIS_URL:"redis://redis:6379",CLOUD_TRUST_PROXY:"true",
  CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
  WORKER_INTERNAL_URL:"http://decoder-worker:8787",
  CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON:"",CLOUD_FORCE_MAINTENANCE:"false",
};
Object.assign(process.env,env);
const authCode="spqa-"+"Q".repeat(48);
const req=(body,path="/api/v1/session/qa")=>new Request("https://api.spdecode.xyz"+path,{
  method:"POST",headers:{"Content-Type":"application/json","X-Real-IP":"192.0.2.40"},body:JSON.stringify(body),
});
const opts=r=>({storeProvider:async()=>r});
test("QA is time-limited and never unlocks production without explicit flags",()=>{
  assert.equal(settings({...env,CLOUD_QA_ENABLED:"false"}).configured,false);
  assert.equal(settings({...env,CLOUD_QA_EXPIRES_AT:String(Math.floor(Date.now()/1000)-1)}).configured,false);
  assert.equal(settings({...env,CLOUD_QA_EXPIRES_AT:String(Math.floor(Date.now()/1000)+86401)}).configured,false);
  assert.equal(settings({...env,CLOUD_WORKER_TOKEN:"x"}).configured,false);
  assert.equal(settings({...env,CLOUD_API_ENABLED:"false"}).configured,false);
  assert.equal(settings({...env,CLOUD_TRUST_PROXY:"false"}).configured,false);
  assert.equal(settings(env).qaActive,true);
  assert.equal(settings(env).configured,true);
  assert.equal(settings(env).account,null);
});
test("QA requires code, challenge, IP binding; sessions are signed and revocable",async()=>{
  const redis=new RedisFake();
  await redis.set("spc3:qa:code",createHmac("sha256",env.CLOUD_SESSION_SIGNING_KEY)
    .update(authCode).digest("hex"));
  const challenge=await createChallenge(redis,req({},"/api/v1/session/challenge"));
  const invalid=await qaSessionRequest(req({challengeId:challenge.challengeId,qaCode:"spqa-"+"B".repeat(48)}),opts(redis));
  assert.equal(invalid.status,403);
  const replay=await qaSessionRequest(req({challengeId:challenge.challengeId,qaCode:authCode}),opts(redis));
  assert.equal(replay.status,401);
  const okChallenge=await createChallenge(redis,req({},"/api/v1/session/challenge"));
  const granted=await qaSessionRequest(req({challengeId:okChallenge.challengeId,qaCode:authCode}),opts(redis));
  assert.equal(granted.status,201);
  const result=await granted.json();
  assert.equal(result.tokenType,"Bearer");
  assert.equal(typeof result.accessToken,"string");
  const check=new Request("https://api.spdecode.xyz/api/v1/decode/file",{
    headers:{authorization:"Bearer "+result.accessToken,"X-Real-IP":"192.0.2.40"}
  });
  assert.ok((await requireSession(redis,check,settings())).jti);
  process.env.CLOUD_QA_ENABLED="false";
  try {
    assert.equal(await requireSession(redis,check,settings()),null);
  } finally {process.env.CLOUD_QA_ENABLED="true";}
});
test("QA refuses anonymous, forged, malformed and expired code flows",async()=>{
  const redis=new RedisFake();
  assert.equal((await qaSessionRequest(req({challengeId:"x",qaCode:authCode}),opts(redis))).status,400);
  const testChallenge=await createChallenge(redis,req({},"/api/v1/session/challenge"));
  const reply=await qaSessionRequest(req({challengeId:testChallenge.challengeId,qaCode:authCode}),opts(redis));
  assert.equal(reply.status,403);
  process.env.CLOUD_QA_ENABLED="false";
  try {
    const denied=await qaSessionRequest(req({}),opts(redis));
    assert.ok([403,503].includes(denied.status));
  }finally{process.env.CLOUD_QA_ENABLED="true";}
});

