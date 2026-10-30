import { notificationFeedRequest } from "./app-notifications.mjs";
import { randomBytes, randomUUID } from "node:crypto";
import { limits } from "./c3-config.mjs";
import { v2Settings } from "./v2-config.mjs";
import {v2PlayPolicyStatus} from "./v2-play-policy.mjs";
import {v2PolicyStatus} from "./v2-availability-policy.mjs";
import { store, ipKey, throttle } from "./c3-store.mjs";
import { sign, verifySignature } from "./c3-session.mjs";
import { decodePlayToken, checkIntegrityVerdict } from "./c3-integrity.mjs";
import { integrityNonce, publicKey, verifyProof, sha256 } from "./v2-proof.mjs";
import { bindVerifiedRequest } from "./v2-bound-request.mjs";
import { maintenanceEnabled } from "./c6-ops-store.mjs";
import { jsonReply } from "./responses.mjs";
import { routes,metadata,bodyLimit } from "./v2-routes.mjs";
import { attestationChallenge,registeredKey,rememberKey,verifyHardware } from "./device-security.mjs";
import { validBoundClaims,acceptBoundProof } from "./bound-auth.mjs";
import { actionChallenge,verifyAction } from "./action-integrity.mjs";
import {hpkeServerKey,openRequest,encryptedReply} from "./v2-hpke.mjs";

const fail=(code,status)=>jsonReply({error:{code}},status);
const record=value=>value && typeof value==="object" && !Array.isArray(value);
const audience="spdecode-android-v2";
// Public protocol IDs, never caller-supplied executable routes.

async function readBytes(request,max,encrypted=false) {
  const expected=encrypted?"application/octet-stream":"application/json";
  if(request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()!==expected ||
     !request.body || request.headers.has("content-encoding"))throw Error("INVALID_REQUEST");
  const length=request.headers.get("content-length");
  if(length && (!/^\d+$/.test(length)||Number(length)>max))throw Error("INPUT_TOO_LARGE");
  const reader=request.body.getReader(),parts=[];let size=0;
  try {
    for(;;) {
      const {done,value}=await reader.read();if(done)break;
      size+=value.length;
      if(size>max){await reader.cancel();throw Error("INPUT_TOO_LARGE");}
      parts.push(Buffer.from(value));
    }
  } finally {reader.releaseLock();}
  const bytes=Buffer.concat(parts);
  if(!encrypted) {
    try{JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
    catch{throw Error("INVALID_REQUEST");}
  }
  return bytes;
}
async function dispatch(operation,request) {
  if(operation===17)return notificationFeedRequest(request);
  // Explicit imports let Next trace standalone dependencies.
  const handlers={
    4:()=>import("../app/api/v1/npvs/identity/route.js"),
    5:()=>import("../app/api/v1/decode/file/route.js"),
    6:()=>import("../app/api/v1/decode/text/route.js"),
    7:()=>import("../app/api/v1/decode/import/cloud/route.js"),
    8:()=>import("../app/api/v1/decode/import/http-custom/route.js"),
    9:()=>import("../app/api/v1/decode/import/catalog/remote/route.js"),
    10:()=>import("../app/api/v1/server-vpn/catalog/route.js"),
    11:()=>import("../app/api/v1/server-vpn/icon/route.js"),
    12:()=>import("../app/api/v1/server-vpn/decode/route.js"),
    13:()=>import("../app/api/v1/server-vpn/watch/route.js"),
    14:()=>import("../app/api/v1/whats-new/route.js"),
    15:()=>import("../app/api/v1/telemetry/route.js"),
  };
  return (await handlers[operation]()).POST(request);
}
export async function transportRequest(request,options={}) {
  // Check both server-controlled policies before processing even a bootstrap request.
  let availability,playPolicy;
  try{
    [availability,playPolicy]=await Promise.all([
      (options.availabilityPolicyLoader||v2PolicyStatus)(),
      (options.playPolicyLoader||v2PlayPolicyStatus)()
    ]);
  }catch{return fail("SERVICE_UNAVAILABLE",503);}
  if(!availability.enabled)return fail("V2_API_DISABLED",410);
  const cfg=v2Settings(options.env||process.env,{playIntegrityRequired:playPolicy.integrityRequired});
  if(!cfg.configured)return fail("SERVICE_UNAVAILABLE",503);
  const url=new URL(request.url),header=request.headers.get("x-sp-operation")||"";
  if(request.method!=="POST" || url.search || !/^(1|2|[4-9]|1[0-7])$/.test(header))
    return fail("INVALID_REQUEST",400); // No QA/beta or arbitrary proxy.
  const op=Number(header);
  let envelope=null;
  const sendSecure=(reply)=>envelope?encryptedReply(envelope,reply.status,reply):reply;
  const failSecure=(code,status)=>sendSecure(fail(code,status));
  try {
    const redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis))return fail("SERVICE_UNAVAILABLE",503);
    const ip=ipKey(request);
    if(!await throttle(redis,"spc2:edge:"+ip,300,60))return fail("RATE_LIMITED",429);
    let bearer="",claims;
    // Reject anonymous/expired callers before buffering their large payload.
    if(op>=4) {
      const authorization=request.headers.get("authorization")||"";
      if(!authorization.startsWith("Bearer "))return fail("UNAUTHORIZED",401);
      bearer=authorization.slice(7);claims=verifySignature(bearer,cfg.signingKey,undefined,audience);
      if(!await validBoundClaims(redis,claims,cfg))return fail("UNAUTHORIZED",401);
    }
    // Bootstrap contains only public handshake metadata. Enforce binary
    // encryption for admission and authenticated operations when enabled.
    const recipient=cfg.hpkeRequired?hpkeServerKey(options.env||process.env):null;
    const encrypted=cfg.hpkeRequired && op!==1;
    // Check anonymous admission budget before any X25519 private-key work.
    if(op===2 && !await throttle(redis,"spc2:admission-rate:"+ip,20,900))
      return fail("RATE_LIMITED",429);
    const wire=await readBytes(request,bodyLimit(op)+(encrypted?64:0),encrypted);
    if(encrypted)envelope=openRequest(wire,recipient,{
      operation:op,version:request.headers.get("x-spdecode-app-version")||"",
      timestamp:request.headers.get("x-sp-timestamp")||"",
      nonce:request.headers.get("x-sp-nonce")||"",bearer
    });
    const bytes=envelope?envelope.clear:wire;
    if(bytes.length>bodyLimit(op))return failSecure("INPUT_TOO_LARGE",413);
    if(encrypted) {
      try{JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
      catch{return failSecure("INVALID_REQUEST",400);}
    }
    if(op===1) {
      if(!await throttle(redis,"spc2:challenge-rate:"+ip,15,900))return fail("RATE_LIMITED",429);
      if(!await throttle(redis,"spsec:challenge:global",300,60))return fail("RATE_LIMITED",429);
      const body=JSON.parse(bytes);
      if(!record(body) || Object.keys(body).join(",")!=="publicKey" || !publicKey(body.publicKey))
        return fail("INVALID_REQUEST",400);
      const proofNonce=verifyProof(request,op,bytes,"",body.publicKey);
      if(!proofNonce)return fail("INVALID_REQUEST",400);
      const keyId=sha256(body.publicKey);
      if(!await throttle(redis,"spc2:key-admission:"+keyId,20,900))return fail("RATE_LIMITED",429);
      if(await redis.set("spc2:bootstrap:"+keyId+":"+sha256(proofNonce),"1",{EX:90,NX:true})!=="OK")
        return fail("INVALID_REQUEST",400);
      const challengeId=randomUUID(),nonce=randomBytes(32).toString("base64url");
      const registered=await registeredKey(redis,body.publicKey,cfg);
      // A beta session must have a hardware-verified app version and signing identity.
      // Previously registered strict-mode keys without version evidence re-enroll.
      const hardwareNeeded=cfg.requireHardware&&!registered;
      const value={nonce,publicKey:body.publicKey,ip,created:Date.now(),hardwareNeeded};
      if(await redis.set("spc2:challenge:"+challengeId,JSON.stringify(value),{EX:120,NX:true})!=="OK")
        return fail("SERVICE_UNAVAILABLE",503);
      return jsonReply({apiVersion:"v2",challengeId,nonce,expiresIn:120,integrityRequired:cfg.playIntegrityRequired,
        keyAttestationRequired:hardwareNeeded,hardwareLevel:cfg.hardwareLevel,
        hpkeRequired:cfg.hpkeRequired,
        ...(cfg.hpkeRequired?{hpkePublicKey:recipient.publicKey}:{}),
        ...(hardwareNeeded?{attestationChallenge:attestationChallenge(nonce,challengeId,body.publicKey)}:{})},201);
    }
    if(op===2) {
      const body=JSON.parse(bytes);
      if(!record(body) || !["challengeId,integrityToken","certificateChain,challengeId,integrityToken,publicKey"].includes(Object.keys(body).sort().join(",")) ||
         !/^[0-9a-f-]{36}$/.test(body.challengeId) || typeof body.integrityToken!=="string" ||
         (cfg.playIntegrityRequired ?
          (body.integrityToken.length<80||body.integrityToken.length>16384) :
          body.integrityToken!==""))return failSecure("INVALID_REQUEST",400);
      const raw=await redis.getDel("spc2:challenge:"+body.challengeId);
      if(!raw)return failSecure("EXPIRED_CHALLENGE",401);
      const challenge=JSON.parse(raw);
      const sessionKey=challenge.hardwareNeeded?body.publicKey:challenge.publicKey;
      if(challenge.ip!==ip || Date.now()-challenge.created>120000 || challenge.created>Date.now()+5000 ||
         !verifyProof(request,op,wire,"",sessionKey))return failSecure("INTEGRITY_REJECTED",403);
      if(!challenge.hardwareNeeded&&(body.publicKey!==undefined||body.certificateChain!==undefined))return failSecure("INVALID_REQUEST",400);
      const nonce=integrityNonce(challenge.nonce,body.challengeId,sessionKey);
      // Injection is server-test only. HTTP callers never provide verdict JSON.
      let verdict=null;
      if(cfg.playIntegrityRequired){
        verdict=await (options.decodeIntegrity||decodePlayToken)(body.integrityToken,cfg);
        if(!checkIntegrityVerdict(verdict,{...cfg,nonce}))return failSecure("INTEGRITY_REJECTED",403);
      }
      let hardware=await registeredKey(redis,sessionKey,cfg);
      if(challenge.hardwareNeeded) {
        if(!await throttle(redis,"spsec:enroll-ip:"+ip,12,3600) ||
           !await throttle(redis,"spsec:enroll-global",120,3600))return failSecure("RATE_LIMITED",429);
        const result=await (options.verifyHardware||verifyHardware)(body.certificateChain,
          attestationChallenge(challenge.nonce,body.challengeId,challenge.publicKey),sessionKey,cfg);
        if(result?.valid!==true || result.publicKey!==sessionKey || !["tee","strongbox"].includes(result.level) ||
           (cfg.hardwareLevel==="strongbox"&&result.level!=="strongbox") ||
           (!cfg.playIntegrityRequired&&(!Number.isSafeInteger(result.versionCode)||
              result.versionCode<cfg.minimumVersionCode)) ||
           !await rememberKey(redis,sessionKey,result.level,cfg,result.versionCode))
          return failSecure("INTEGRITY_REJECTED",403);
        hardware=await registeredKey(redis,sessionKey,cfg);
      }
      if(cfg.requireHardware&&!hardware)return failSecure("INTEGRITY_REJECTED",403);
      // In beta, the hardware verifier attests the package, version and signing cert;
      // neither a caller-provided version nor a self-declared signature is accepted.
      if(!cfg.playIntegrityRequired && (!hardware || !Number.isSafeInteger(hardware.versionCode) ||
         hardware.versionCode<cfg.minimumVersionCode))return failSecure("INTEGRITY_REJECTED",403);
      const app=verdict?.tokenPayloadExternal?.appIntegrity;
      const now=Math.floor(Date.now()/1000),jti=randomUUID();
      const claims={iss:"spdecode-cloud",aud:audience,scope:"decode",iat:now,exp:now+300,jti,
        key:sessionKey,hardware:!!hardware,
        playIntegrityVerified:cfg.playIntegrityRequired,
        versionCode:cfg.playIntegrityRequired?Number(app.versionCode):hardware.versionCode,
        certificates:cfg.playIntegrityRequired?
          app.certificateSha256Digest.map(x=>Buffer.from(x,"base64url").toString("hex")):
          cfg.certificateDigests.slice(),epoch:cfg.epoch};
      if(await redis.set("spc2:session:"+jti,"1",{EX:300,NX:true})!=="OK")return failSecure("SERVICE_UNAVAILABLE",503);
      return sendSecure(jsonReply({apiVersion:"v2",accessToken:sign(claims,cfg.signingKey),tokenType:"Bearer",expiresIn:300,
        actionIntegrityRequired:cfg.requireAction},201));
    }
    if([10,11].includes(op) && claims.versionCode>=35 && !publicKey(JSON.parse(bytes).catalogKey))
      return failSecure("INVALID_REQUEST",400);
    const authorized=await acceptBoundProof(redis,request,op,wire,bearer,claims);
    if(!authorized)return failSecure("UNAUTHORIZED",401);
    if(authorized.rateLimited)return failSecure("RATE_LIMITED",429);
    if(op===16) {
      if(!await throttle(redis,"spsec:action-rate:"+sha256(claims.key),20,60))return failSecure("RATE_LIMITED",429);
      const value=await actionChallenge(redis,claims,JSON.parse(bytes),cfg);
      return value?sendSecure(jsonReply(value,201)):failSecure("INVALID_REQUEST",400);
    }
    if(!await verifyAction(redis,request,op,bytes,claims,cfg,options))return failSecure("INTEGRITY_REJECTED",403);
    const headers=new Headers(request.headers);
    headers.delete("content-length");
    // The worker-facing internal route receives the authenticated clear JSON,
    // never the encrypted binary envelope or its octet-stream Content-Type.
    headers.set("content-type","application/json");
    headers.delete("x-sp-envelope");
    const internal=new Request(new URL("/api/v1/"+routes[op],url),{
      method:"POST",headers,body:bytes,signal:request.signal});
    bindVerifiedRequest(internal,claims);
    return sendSecure(await (options.dispatch||dispatch)(op,internal));
  } catch(error) {
    if(error?.message==="INPUT_TOO_LARGE")return failSecure("INPUT_TOO_LARGE",413);
    if(error?.message==="INVALID_REQUEST")return failSecure("INVALID_REQUEST",400);
    return failSecure("SERVICE_UNAVAILABLE",503);
  }
}

