import { randomBytes, randomUUID } from "node:crypto";
import { limits } from "./c3-config.mjs";
import { v2Settings } from "./v2-config.mjs";
import { store, ipKey, throttle } from "./c3-store.mjs";
import { sign, verifySignature } from "./c3-session.mjs";
import { decodePlayToken, checkIntegrityVerdict } from "./c3-integrity.mjs";
import { integrityNonce, publicKey, verifyProof, sha256 } from "./v2-proof.mjs";
import { bindVerifiedRequest } from "./v2-bound-request.mjs";
import { maintenanceEnabled } from "./c6-ops-store.mjs";
import { jsonReply } from "./responses.mjs";

const fail=(code,status)=>jsonReply({error:{code}},status);
const record=value=>value && typeof value==="object" && !Array.isArray(value);
const audience="spdecode-android-v2";
// Public protocol IDs, never caller-supplied executable routes.
const routes=Object.freeze({
  4:"npvs/identity",5:"decode/file",6:"decode/text",7:"decode/import/cloud",
  8:"decode/import/http-custom",9:"decode/import/catalog/remote",10:"server-vpn/catalog",
  11:"server-vpn/icon",12:"server-vpn/decode",13:"server-vpn/watch",14:"whats-new",15:"telemetry",
});
const metadata=new Set([10,11,13,14]);
const bodyLimit=op=>op===5?limits.maxJsonBodyBytes:op===6?1024*1024:op===2?19000:4096;

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
  const cfg=v2Settings(options.env||process.env);
  if(!cfg.configured)return fail("SERVICE_UNAVAILABLE",503);
  const url=new URL(request.url),header=request.headers.get("x-sp-operation")||"";
  if(request.method!=="POST" || url.search || !/^(1|2|[4-9]|1[0-5])$/.test(header))
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
      if(!claims || claims.channel || claims.epoch!==cfg.epoch || !Number.isSafeInteger(claims.versionCode) ||
         claims.versionCode<cfg.minimumVersionCode || !Array.isArray(claims.certificates) || !claims.certificates.length ||
         claims.certificates.some(x=>!cfg.certificateDigests.includes(x)) ||
         await redis.get("spc2:session:"+claims.jti)!=="1")return fail("UNAUTHORIZED",401);
    }
    const bytes=await readBytes(request,bodyLimit(op));
    if(op===1) {
      if(!await throttle(redis,"spc2:challenge-rate:"+ip,15,900))return fail("RATE_LIMITED",429);
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
      const value={nonce,publicKey:body.publicKey,ip,created:Date.now()};
      if(await redis.set("spc2:challenge:"+challengeId,JSON.stringify(value),{EX:120,NX:true})!=="OK")
        return fail("SERVICE_UNAVAILABLE",503);
      return jsonReply({apiVersion:"v2",challengeId,nonce,expiresIn:120,integrityRequired:true},201);
    }
    if(op===2) {
      if(!await throttle(redis,"spc2:admission-rate:"+ip,20,900))return fail("RATE_LIMITED",429);
      const body=JSON.parse(bytes);
      if(!record(body) || Object.keys(body).sort().join(",")!=="challengeId,integrityToken" ||
         !/^[0-9a-f-]{36}$/.test(body.challengeId) || typeof body.integrityToken!=="string" ||
         body.integrityToken.length<80 || body.integrityToken.length>16384)return fail("INVALID_REQUEST",400);
      const raw=await redis.getDel("spc2:challenge:"+body.challengeId);
      if(!raw)return fail("EXPIRED_CHALLENGE",401);
      const challenge=JSON.parse(raw);
      if(challenge.ip!==ip || Date.now()-challenge.created>120000 || challenge.created>Date.now()+5000 ||
         !verifyProof(request,op,bytes,"",challenge.publicKey))return fail("INTEGRITY_REJECTED",403);
      const nonce=integrityNonce(challenge.nonce,body.challengeId,challenge.publicKey);
      // Injection is server-test only. HTTP callers never provide verdict JSON.
      const verdict=await (options.decodeIntegrity||decodePlayToken)(body.integrityToken,cfg);
      if(!checkIntegrityVerdict(verdict,{...cfg,nonce}))return fail("INTEGRITY_REJECTED",403);
      const app=verdict.tokenPayloadExternal.appIntegrity;
      const now=Math.floor(Date.now()/1000),jti=randomUUID();
      const claims={iss:"spdecode-cloud",aud:audience,scope:"decode",iat:now,exp:now+300,jti,
        key:challenge.publicKey,versionCode:Number(app.versionCode),
        certificates:app.certificateSha256Digest.map(x=>Buffer.from(x,"base64url").toString("hex")),epoch:cfg.epoch};
      if(await redis.set("spc2:session:"+jti,"1",{EX:300,NX:true})!=="OK")return fail("SERVICE_UNAVAILABLE",503);
      return jsonReply({apiVersion:"v2",accessToken:sign(claims,cfg.signingKey),tokenType:"Bearer",expiresIn:300},201);
    }
    const nonce=verifyProof(request,op,bytes,bearer,claims.key);
    if(!nonce)return fail("UNAUTHORIZED",401);
    if(await redis.set("spc2:proof:"+claims.jti+":"+sha256(nonce),"1",{EX:90,NX:true})!=="OK")
      return fail("UNAUTHORIZED",401);
    const lightweight=metadata.has(op),limit=lightweight?180:limits.requestsPerSessionMinute;
    if(!await throttle(redis,"spc2:"+(lightweight?"metadata:":"work:")+claims.jti,limit,60) ||
       (!lightweight && !await throttle(redis,"spc2:work-ip:"+ip,limits.requestsPerIpWindow,60)))
      return fail("RATE_LIMITED",429);
    const headers=new Headers(request.headers);headers.delete("content-length");
    const internal=new Request(new URL("/api/v1/"+routes[op],url),{
      method:"POST",headers,body:bytes,signal:request.signal});
    bindVerifiedRequest(internal,claims);
    return await (options.dispatch||dispatch)(op,internal);
  } catch(error) {
    if(error?.message==="INPUT_TOO_LARGE")return fail("INPUT_TOO_LARGE",413);
    if(error?.message==="INVALID_REQUEST")return fail("INVALID_REQUEST",400);
    return fail("SERVICE_UNAVAILABLE",503);
  }
}
