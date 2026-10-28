import {test} from "node:test";
import assert from "node:assert/strict";
import {scryptSync,randomBytes} from "node:crypto";
import {readFileSync} from "node:fs";
import {settings} from "../lib/c3-config.mjs";
import {admissionPolicy,setAdmissionPolicy,MAX_BETA_SECONDS} from "../lib/c11-play-admission.mjs";
import {createChallenge,issueSession,verifySignature} from "../lib/c3-session.mjs";
import {playAdmissionRequest,loginRequest} from "../lib/c6-admin-api.mjs";
class Redis{
 constructor(){this.values=new Map();this.counts=new Map();}
 async get(k){return this.values.get(k)??null;}
 async set(k,v,{NX}={}){if(NX&&this.values.has(k))return null;this.values.set(k,v);return "OK";}
 async getDel(k){const a=await this.get(k);this.values.delete(k);return a;}
 async del(k){return this.values.delete(k)?1:0;}
 async incr(k){const n=(this.counts.get(k)||0)+1;this.counts.set(k,n);return n;}
 async expire(){return 1;}
 async ping(){return "PONG";}
}
const secureEnv={CLOUD_API_ENABLED:"true",CLOUD_WORKER_TOKEN:"k".repeat(48),
 CLOUD_SESSION_SIGNING_KEY:"s".repeat(48),CLOUD_REDIS_URL:"redis://redis:6379",
 CLOUD_TRUST_PROXY:"true",CLOUD_GOOGLE_PLAY_PACKAGE:"com.ghostdeveloper.spdecode",
 CLOUD_BETA_ADMISSION_ENABLED:"true"};
const req=(path,body,headers={})=>new Request("https://panel.example.test"+path,{
 method:"POST",headers:{"Content-Type":"application/json","X-Real-IP":"198.51.100.7",...headers},
 body:JSON.stringify(body)});
test("closed by default, explicit VPS opt-in required; no Google credential needed only during beta",async()=>{
 const redis=new Redis();
 assert.equal((await admissionPolicy(redis,{})).integrityRequired,true);
 await assert.rejects(()=>setAdmissionPolicy(redis,false,{}),/BETA_LOCKED/);
 assert.equal(settings({...secureEnv,CLOUD_BETA_ADMISSION_ENABLED:"false"}).configured,false);
 assert.equal(settings(secureEnv).configured,true);
 const beta=await setAdmissionPolicy(redis,false,secureEnv);
 assert.equal(beta.integrityRequired,false);
 assert.equal(beta.locked,false);
 assert.equal((await admissionPolicy(redis,secureEnv,{now:Date.now()+MAX_BETA_SECONDS*1000+10})).integrityRequired,true);
 assert.equal((await setAdmissionPolicy(redis,true,secureEnv)).integrityRequired,true);
 assert.equal((await admissionPolicy(redis,secureEnv)).integrityRequired,true);
});
test("beta keeps nonce, IP binding, replay protection and five-minute signed sessions",async()=>{
 const redis=new Redis(),cfg=settings(secureEnv);
 const policy=await setAdmissionPolicy(redis,false,secureEnv);
 const source=req("/api/v1/session/challenge",{});
 const challenge=await createChallenge(redis,source);
 const issued=await issueSession(redis,source,{challengeId:challenge.challengeId},cfg,async()=>{throw Error("Google must not be called in beta");},policy);
 assert.ok(issued.accessToken);
 const claims=verifySignature(issued.accessToken,cfg.signingKey);
 assert.ok(claims&&claims.exp-claims.iat<=300);
 assert.equal((await issueSession(redis,source,{challengeId:challenge.challengeId},cfg,async()=>true,policy)).error,"EXPIRED_CHALLENGE");
 const second=await createChallenge(redis,source);
 const token=await issueSession(redis,source,{challengeId:second.challengeId,integrityToken:"forged"},cfg,async()=>true,policy);
 assert.equal(token.error,"INVALID_REQUEST");
 const third=await createChallenge(redis,source);
 const wrongIp=req("/api/v1/session",{challengeId:third.challengeId},{"X-Real-IP":"198.51.100.8"});
 assert.equal((await issueSession(redis,wrongIp,{challengeId:third.challengeId},cfg,async()=>true,policy)).error,"EXPIRED_CHALLENGE");
 const strict=await setAdmissionPolicy(redis,true,secureEnv);
 const fourth=await createChallenge(redis,source);
 assert.equal((await issueSession(redis,source,{challengeId:fourth.challengeId},cfg,async()=>true,strict)).error,"INTEGRITY_REJECTED");
});
test("admin policy requires valid session cookie + CSRF origin and cannot last indefinitely",async()=>{
 const redis=new Redis(),salt=randomBytes(16);
 const password="production panel test password 2026";
 const adminEnv={...secureEnv,CLOUD_ADMIN_ENABLED:"true",CLOUD_ADMIN_USERNAME:"ghostadmin",
  CLOUD_ADMIN_PASSWORD_SCRYPT:"scrypt$16384$8$1$"+salt.toString("hex")+"$"+
    scryptSync(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024}).toString("hex"),
  CLOUD_ADMIN_SESSION_KEY:"a".repeat(48),CLOUD_ADMIN_PUBLIC_ORIGIN:"https://panel.example.test"};
 Object.assign(process.env,adminEnv);
 const args={storeProvider:async()=>redis};
 const headers={Origin:adminEnv.CLOUD_ADMIN_PUBLIC_ORIGIN,"X-SPDecode-Admin-Action":"1"};
 const anonymous=await playAdmissionRequest(req("/api/admin/play-admission",{integrityRequired:false},headers),args);
 assert.equal(anonymous.status,401);
 const login=await loginRequest(req("/api/admin/login",{username:"ghostadmin",password},headers),args);
 assert.equal(login.status,200);
 const cookie=login.headers.get("set-cookie").split(";")[0];
 const auth={...headers,Cookie:cookie};
 assert.equal((await playAdmissionRequest(req("/api/admin/play-admission",{integrityRequired:false},{...auth,Origin:"https://evil.invalid"}),args)).status,403);
 assert.equal((await playAdmissionRequest(req("/api/admin/play-admission",{integrityRequired:"false"},auth),args)).status,400);
 const updated=await playAdmissionRequest(req("/api/admin/play-admission",{integrityRequired:false},auth),args);
 assert.equal(updated.status,200);
 const body=await updated.json();
 assert.equal(body.playAdmission.integrityRequired,false);
 assert.ok(Date.parse(body.playAdmission.betaUntil)>Date.now());
 assert.equal((await playAdmissionRequest(req("/api/admin/play-admission",{integrityRequired:true},auth),args)).status,200);
 assert.equal((await admissionPolicy(redis,secureEnv)).integrityRequired,true);
});
test("signed Play AAB and external beta APK are generated without changing application ID",()=>{
 const read=p=>readFileSync(new URL("../../../"+p,import.meta.url),"utf8");
 const gradle=read("android/app/build.gradle.kts");
 const workflow=read(".github/workflows/play-beta-artifacts.yml");
 const integrity=read("android/app/src/main/java/com/ghostdeveloper/spdecode/ReleaseIntegrity.kt");
 const client=read("android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt");
 assert.match(gradle,/applicationId = "com\.ghostdeveloper\.spdecode"/);
 assert.match(gradle,/targetSdk = 36/);
 assert.match(gradle,/compileSdk = 36/);
 assert.match(workflow,/:app:assembleRelease :app:bundleRelease/);
 assert.match(workflow,/SPDECODE_SIGNING_KEYSTORE_BASE64/);
  const version=gradle.match(/versionName = "(\d+\.\d+\.\d+)"/)?.[1];
  const code=gradle.match(/versionCode = (\d+)/)?.[1];
  assert.ok(version && code && Number(code)>26,"Play update must advance beyond 1.1.5 (26)");
  assert.ok(workflow.includes("SP-DECODE-v"+version+"-play-closed-test-signed.aab"));
  assert.ok(workflow.includes("SP-DECODE-v"+version+"-beta-external-signed.apk"));
 assert.match(integrity,/PLAY_APP_SIGNER_SHA256/);
 assert.match(client,/CloudRequestProof\.integrityNonce/);
 assert.match(client,/!challenge\.optBoolean\("integrityRequired", false\)/);
});
