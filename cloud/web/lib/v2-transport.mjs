import { raspActions, decideRasp, recordRasp } from "./rasp-policy.mjs";
import { notificationFeedRequest } from "./app-notifications.mjs";
import { randomBytes, randomUUID } from "node:crypto";
import { limits } from "./c3-config.mjs";
import { v2Settings } from "./v2-config.mjs";
import {v2PlayPolicyStatus} from "./v2-play-policy.mjs";
import {v2DevicePolicyStatus} from "./v2-device-admission-policy.mjs";
import {recordAdmission,playSignals} from "./v2-admission-diagnostics.mjs";
import {v2PolicyStatus} from "./v2-availability-policy.mjs";
import { store, ipKey, throttle } from "./c3-store.mjs";
import { sign, verifySignature } from "./c3-session.mjs";
import { decodePlayToken, checkIntegrityVerdict, integrityVerdictReason } from "./c3-integrity.mjs";
import { integrityNonce, publicKey, verifyProof, sha256 } from "./v2-proof.mjs";
import { bindVerifiedRequest } from "./v2-bound-request.mjs";
import { maintenanceEnabled } from "./c6-ops-store.mjs";
import { jsonReply } from "./responses.mjs";
import { routes,metadata,bodyLimit } from "./v2-routes.mjs";
import { attestationChallenge,registeredKey,rememberKey,verifyHardware } from "./device-security.mjs";
import { validBoundClaims,acceptBoundProof } from "./bound-auth.mjs";
import { actionChallenge,verifyAction } from "./action-integrity.mjs";
import { openHpkeRequest, unpackHpkeBody, sealHpkeReply, isHpkeEnabled, requiresHpke, HPKE_MAX_BYTES } from "./v2-hpke.mjs";

const fail=(code,status)=>jsonReply({error:{code}},status);
const record=value=>value && typeof value==="object" && !Array.isArray(value);
const audience="spdecode-android-v2";
// Public protocol IDs, never caller-supplied executable routes.

async function readBytes(request,max) {
  if(request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()!=="application/json" ||
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
  try{JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
  catch{throw Error("INVALID_REQUEST");}
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
    18:()=>import("../app/api/v1/feedback/route.js"),
    19:()=>import("../app/api/v1/server-vpn/manifest/route.js"),
    20:()=>import("../app/api/v1/server-vpn/chunk/route.js"),
    21:()=>import("../app/api/v1/apk-qa/start/route.js"),
    22:()=>import("../app/api/v1/apk-qa/chunk/route.js"),
    23:()=>import("../app/api/v1/apk-qa/finish/route.js"),
    24:()=>import("../app/api/v1/apk-qa/result/route.js"),
  };
  return (await handlers[operation]()).POST(request);
}
async function jsonTransportCore(request,options={}) {
  // Check both server-controlled policies before processing even a bootstrap request.
  let availability,playPolicy,devicePolicy;
  try{
    [availability,playPolicy,devicePolicy]=await Promise.all([
      (options.availabilityPolicyLoader||v2PolicyStatus)(),
      (options.playPolicyLoader||v2PlayPolicyStatus)(),
      (options.devicePolicyLoader||v2DevicePolicyStatus)()
    ]);
  }catch{return fail("SERVICE_UNAVAILABLE",503);}
  if(!availability.enabled)return fail("V2_API_DISABLED",410);
  const cfg={...v2Settings(options.env||process.env,{playIntegrityRequired:playPolicy.integrityRequired,playPolicy:playPolicy.version===2?playPolicy:null}),
    deviceRevision:devicePolicy.revision};
  if(!cfg.configured)return fail("SERVICE_UNAVAILABLE",503);
  const url=new URL(request.url),header=request.headers.get("x-sp-operation")||"";
  if(request.method!=="POST" || url.search || !/^(1|2|[4-9]|1[0-9]|2[0-4])$/.test(header))
    return fail("INVALID_REQUEST",400); // No QA/beta or arbitrary proxy.
  const op=Number(header);
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
      if(claims.hpke===true && !options.hpkeWireBytes)
        return fail("ENCRYPTED_TRANSPORT_REQUIRED",426);
    }
    const bytes=await readBytes(request,bodyLimit(op));
    if(op===1) {
      if(!await throttle(redis,"spc2:challenge-rate:"+ip,15,900))return fail("RATE_LIMITED",429);
      if(!await throttle(redis,"spsec:challenge:global",300,60))return fail("RATE_LIMITED",429);
      const body=JSON.parse(bytes);
      if(!record(body) || Object.keys(body).join(",")!=="publicKey" || !publicKey(body.publicKey))
        return fail("INVALID_REQUEST",400);
      const proofNonce=verifyProof(request,op,options.hpkeWireBytes||bytes,"",body.publicKey);
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
      const value={nonce,publicKey:body.publicKey,ip,created:Date.now(),hardwareNeeded,
        transportRevision:request.headers.get("x-spdecode-transport")==="2"?2:1,
        hpke:Boolean(options.hpkeWireBytes)};
      if(await redis.set("spc2:challenge:"+challengeId,JSON.stringify(value),{EX:120,NX:true})!=="OK")
        return fail("SERVICE_UNAVAILABLE",503);
       return jsonReply({apiVersion:"v2",challengeId,nonce,expiresIn:120,integrityRequired:cfg.playIntegrityRequired,
         integrityRequested:cfg.playIntegrityRequested&&Boolean(cfg.account),playMode:cfg.playMode,
        keyAttestationRequired:hardwareNeeded,hardwareLevel:cfg.hardwareLevel,
        ...(hardwareNeeded?{attestationChallenge:attestationChallenge(nonce,challengeId,body.publicKey)}:{})},201);
    }
    if(op===2) {
      if(!await throttle(redis,"spc2:admission-rate:"+ip,20,900))return fail("RATE_LIMITED",429);
      const body=JSON.parse(bytes);
      if(!record(body) || !["challengeId,integrityToken","certificateChain,challengeId,integrityToken,publicKey"].includes(Object.keys(body).sort().join(",")) ||
         !/^[0-9a-f-]{36}$/.test(body.challengeId) || typeof body.integrityToken!=="string" ||
         (body.integrityToken.length>16384 || (body.integrityToken!==""&&body.integrityToken.length<80) ||
          (cfg.playIntegrityRequired&&body.integrityToken==="")))return fail("INVALID_REQUEST",400);
      const raw=await redis.getDel("spc2:challenge:"+body.challengeId);
      if(!raw)return fail("EXPIRED_CHALLENGE",401);
      const challenge=JSON.parse(raw);
      const sessionKey=challenge.hardwareNeeded?body.publicKey:challenge.publicKey;
      if(challenge.ip!==ip || Boolean(challenge.hpke)!==Boolean(options.hpkeWireBytes) ||
         Date.now()-challenge.created>120000 || challenge.created>Date.now()+5000 ||
         !verifyProof(request,op,options.hpkeWireBytes||bytes,"",sessionKey))return fail("INTEGRITY_REJECTED",403);
      if(!challenge.hardwareNeeded&&(body.publicKey!==undefined||body.certificateChain!==undefined))return fail("INVALID_REQUEST",400);
      const nonce=integrityNonce(challenge.nonce,body.challengeId,sessionKey);
      // Injection is server-test only. HTTP callers never provide verdict JSON.
       let verdict=null;
       if(body.integrityToken!==""&&cfg.playMode!=="off"){
         try{verdict=await (options.decodeIntegrity||decodePlayToken)(body.integrityToken,cfg);}
         catch{
           await recordAdmission(redis,"SESSION","UNAVAILABLE","PLAY_UNAVAILABLE");
           if(cfg.playIntegrityRequired)return fail("INTEGRITY_UNAVAILABLE",503);
         }
       }
       const playReason=verdict===null?"PLAY_NOT_PROVIDED":integrityVerdictReason(verdict,{...cfg,nonce});
       const playValid=playReason===null;
       if(cfg.playIntegrityRequired&&!playValid){
         await recordAdmission(redis,"SESSION","OBSERVED",playReason,playSignals(verdict));
         return fail("PLAY_POLICY_REJECTED",403);
       }
       if(!cfg.playIntegrityRequired)await recordAdmission(redis,"SESSION","OBSERVED",
         cfg.playMode==="off"?"PLAY_DISABLED":verdict?(playValid?"PLAY_VALID":playReason):"PLAY_NOT_PROVIDED",playSignals(verdict));
      let hardware=await registeredKey(redis,sessionKey,cfg);
      if(challenge.hardwareNeeded) {
        if(!await throttle(redis,"spsec:enroll-ip:"+ip,12,3600) ||
           !await throttle(redis,"spsec:enroll-global",120,3600))return fail("RATE_LIMITED",429);
        const result=await (options.verifyHardware||verifyHardware)(body.certificateChain,
          attestationChallenge(challenge.nonce,body.challengeId,challenge.publicKey),sessionKey,cfg);
        if(result?.valid!==true || result.publicKey!==sessionKey || !["tee","strongbox"].includes(result.level) ||
           (cfg.hardwareLevel==="strongbox"&&result.level!=="strongbox") ||
           (!cfg.playIntegrityRequired&&(!Number.isSafeInteger(result.versionCode)||
              result.versionCode<cfg.minimumVersionCode)) ||
           !await rememberKey(redis,sessionKey,result.level,cfg,result.versionCode))
           {await recordAdmission(redis,"SESSION","OBSERVED","HARDWARE_ATTESTATION");return fail("ATTESTATION_REJECTED",403);}
        hardware=await registeredKey(redis,sessionKey,cfg);
      }
      if(cfg.requireHardware&&!hardware)return fail("INTEGRITY_REJECTED",403);
      // In beta, the hardware verifier attests the package, version and signing cert;
      // neither a caller-provided version nor a self-declared signature is accepted.
      if(!cfg.playIntegrityRequired && (!hardware || !Number.isSafeInteger(hardware.versionCode) ||
         hardware.versionCode<cfg.minimumVersionCode))return fail("INTEGRITY_REJECTED",403);
      const app=verdict?.tokenPayloadExternal?.appIntegrity;
      const now=Math.floor(Date.now()/1000),jti=randomUUID();
       const sessionSeconds=challenge.transportRevision===2?(cfg.sessionSeconds||1800):Math.min(300,cfg.sessionSeconds||300);
       const claims={iss:"spdecode-cloud",aud:audience,scope:"decode",iat:now,exp:now+sessionSeconds,jti,
         policyRevision:cfg.policyRevision,deviceRevision:cfg.deviceRevision,
        key:sessionKey,hardware:!!hardware,hpke:Boolean(options.hpkeWireBytes),
        playIntegrityVerified:cfg.playIntegrityRequired,
        versionCode:cfg.playIntegrityRequired?Number(app.versionCode):hardware.versionCode,
        certificates:cfg.playIntegrityRequired?
          app.certificateSha256Digest.map(x=>Buffer.from(x,"base64url").toString("hex")):
          cfg.certificateDigests.slice(),epoch:cfg.epoch};
       if(await redis.set("spc2:session:"+jti,"1",{EX:sessionSeconds,NX:true})!=="OK")return fail("SERVICE_UNAVAILABLE",503);
       return jsonReply({apiVersion:"v2",accessToken:sign(claims,cfg.signingKey),tokenType:"Bearer",expiresIn:sessionSeconds,
        actionIntegrityRequired:cfg.requireAction,
         actionIntegrityProtocol:"inline-v2",cloudProjectNumber:cfg.cloudProjectNumber,
        raspEnforce:cfg.rasp.mode==="enforce"&&claims.versionCode>=cfg.rasp.minVersion},201);
    }
    if([10,11].includes(op) && claims.versionCode>=35 && !publicKey(JSON.parse(bytes).catalogKey))
      return fail("INVALID_REQUEST",400);
    const authorized=await acceptBoundProof(redis,request,op,bytes,bearer,claims,options.hpkeWireBytes||bytes);
    if(!authorized)return fail("UNAUTHORIZED",401);
    if(authorized.rateLimited)return fail("RATE_LIMITED",429);
    if(op===16) {
      if(!await throttle(redis,"spsec:action-rate:"+sha256(claims.key),20,60))return fail("RATE_LIMITED",429);
      const value=await actionChallenge(redis,claims,JSON.parse(bytes),cfg);
      return value?jsonReply(value,201):fail("INVALID_REQUEST",400);
    }
    try {
      if(!await verifyAction(redis,request,op,options.hpkeWireBytes||bytes,claims,cfg,options)){
        await recordAdmission(redis,"ACTION","REJECTED","PLAY_ACTION");
        return fail("INTEGRITY_REJECTED",403);
      }
    }catch{
      await recordAdmission(redis,"ACTION","UNAVAILABLE","PLAY_UNAVAILABLE");
      return fail("INTEGRITY_UNAVAILABLE",503);
    }
    // Only evaluate reports AFTER independent authentication, replay/budget
    // checks and action Integrity. Parse/strip after proof verification so the
    // authenticated bytes are never replaced by a reserialized body.
    const payload=JSON.parse(bytes);
    let dispatchBytes=bytes;
    if(raspActions.has(op)) {
      const decision=decideRasp(payload?._rasp,claims.versionCode,cfg.rasp);
      await recordRasp(redis,decision,claims.versionCode,cfg.rasp);
      if(decision.deny) {
        await redis.getDel("spc2:session:"+claims.jti);
        return fail("INTEGRITY_REJECTED",403);
      }
      if(record(payload)&&Object.hasOwn(payload,"_rasp")) {
        delete payload._rasp;
        dispatchBytes=Buffer.from(JSON.stringify(payload));
      }
    }
    const headers=new Headers(request.headers);headers.delete("content-length");
    const internal=new Request(new URL("/api/v1/"+routes[op],url),{
      method:"POST",headers,body:dispatchBytes,signal:request.signal});
    bindVerifiedRequest(internal,{...claims,hpke:Boolean(options.hpkeWireBytes)});
    return await (options.dispatch||dispatch)(op,internal);
  } catch(error) {
    if(error?.message==="INPUT_TOO_LARGE")return fail("INPUT_TOO_LARGE",413);
    if(error?.message==="INVALID_REQUEST")return fail("INVALID_REQUEST",400);
    return fail("SERVICE_UNAVAILABLE",503);
  }
}

async function jsonTransportRequest(request,options={}) {
  const response=await jsonTransportCore(request,options);
  if(request.headers.get("x-sp-operation")==="2"){
    try {
      const redis=await (options.storeProvider||store)();
      const reason=response.ok?"SESSION_ISSUED":(await response.clone().json()).error?.code||"SESSION_FAILED";
      await recordAdmission(redis,"SESSION",response.ok?"ACCEPTED":"REJECTED",reason);
    }catch{ /* Metrics do not change the terminal decision. */ }
  }
  return response;
}


/** V2 encrypted branch uses the EXACT existing admission, Play, hardware,
 * PoP, action-integrity and worker contracts after decrypting. All PoP/action
 * hashes bind the outer ciphertext rather than a reserialized JSON payload.
 * Older private beta clients remain on their JSON path until HPKE_ONLY.
 */
async function readHpkeBytes(request,limit) {
  if(request.headers.has("content-encoding")||!request.body)throw Error("HPKE_INVALID");
  const length=request.headers.get("content-length");
  if(length && (!/^\d+$/.test(length)||Number(length)>limit))throw Error("INPUT_TOO_LARGE");
  const reader=request.body.getReader(),parts=[];let size=0;
  try {
    for(;;) {
      const {done,value}=await reader.read();if(done)break;
      size+=value.byteLength;
      if(size>limit){await reader.cancel();throw Error("INPUT_TOO_LARGE");}
      parts.push(Buffer.from(value));
    }
  }finally{reader.releaseLock();}
  return Buffer.concat(parts,size);
}
async function boundedReply(reply) {
  const max=96*1024*1024;
  if(Number(reply.headers.get("content-length"))>max)throw Error("HPKE_REPLY_TOO_LARGE");
  const reader=reply.body?.getReader();if(!reader)return Buffer.alloc(0);
  const chunks=[];let size=0;
  try {
    for(;;) {
      const {done,value}=await reader.read();if(done)break;
      size+=value.byteLength;
      if(size>max){await reader.cancel();throw Error("HPKE_REPLY_TOO_LARGE");}
      chunks.push(Buffer.from(value));
    }
  }finally{reader.releaseLock();}
  return Buffer.concat(chunks,size);
}
export async function transportRequest(request,options={}) {
  const type=request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  const env=options.env||process.env;
  if(type!=="application/octet-stream") {
    if(requiresHpke(env))return fail("ENCRYPTED_TRANSPORT_REQUIRED",426);
    return jsonTransportRequest(request,options);
  }
  if(!isHpkeEnabled(env))return fail("SERVICE_UNAVAILABLE",503);
  const url=new URL(request.url),name=request.headers.get("x-sp-operation")||"";
  if(request.method!=="POST"||url.search||!/^(1|2|[4-9]|1[0-9]|2[0-4])$/.test(name))
    return fail("INVALID_REQUEST",400);
  const op=Number(name);
  if(op>=4 && !(request.headers.get("authorization")||"").startsWith("Bearer "))
    return fail("UNAUTHORIZED",401);
  let opened;
  try {
    // Apply independent edge throttling before accepting large crypto payloads.
    const redis=await (options.storeProvider||store)();
    if(!await throttle(redis,"spc2:hpke-edge:"+ipKey(request),180,60))
      return fail("RATE_LIMITED",429);
    const max=op===5?HPKE_MAX_BYTES:(op===6?1024*1024+512:bodyLimit(op)+512);
    const wire=await readHpkeBytes(request,max);
    opened=await openHpkeRequest(wire,op,env);
    if(await redis.set("spc2:hpke-replay:"+opened.replayId,"1",{EX:150,NX:true})!=="OK")
      return fail("INVALID_REQUEST",400);
    const decoded=unpackHpkeBody(opened.plaintext,op);
    const headers=new Headers(request.headers);
    headers.set("content-type","application/json");
    headers.delete("content-length");headers.delete("content-encoding");
    const internal=new Request(request.url,{method:"POST",headers,body:decoded,signal:request.signal});
    const response=await jsonTransportRequest(internal,{...options,hpkeWireBytes:wire});
    const responseBytes=await boundedReply(response);
    const ciphertext=sealHpkeReply(opened,response.status,responseBytes);
    return new Response(ciphertext,{status:response.status,headers:{
      "Content-Type":"application/octet-stream","Content-Length":String(ciphertext.length),"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"
    }});
  }catch(error) {
    // Do not disclose key IDs, invalid tags, keyring state or parsing exceptions.
    return fail(error?.message==="INPUT_TOO_LARGE"?"INPUT_TOO_LARGE":"INVALID_REQUEST",
      error?.message==="INPUT_TOO_LARGE"?413:400);
  }finally {
    if(opened?.plaintext)opened.plaintext.fill(0);
    if(opened?.responseMaterial)opened.responseMaterial.fill(0);
  }
}
