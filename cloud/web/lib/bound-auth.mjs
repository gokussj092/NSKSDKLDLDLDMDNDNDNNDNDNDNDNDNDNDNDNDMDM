import { verifyProof, sha256 } from "./v2-proof.mjs";
import { registeredKey, keyId, workBudget } from "./device-security.mjs";
import { throttle, ipKey } from "./c3-store.mjs";
import { routes, metadata, uploads, analysisJobs, decodeWork, bodyLimit } from "./v2-routes.mjs";
import { verifyAction } from "./action-integrity.mjs";

export async function validBoundClaims(redis, claims, cfg) {
  return !!claims && !claims.channel && claims.epoch === cfg.epoch &&
    (claims.policyRevision??0)===(cfg.policyRevision??0)&&
    (claims.deviceRevision??0)===(cfg.deviceRevision??0)&&
    Number.isSafeInteger(claims.versionCode) && claims.versionCode >= cfg.minimumVersionCode &&
    Array.isArray(claims.certificates) && claims.certificates.length > 0 &&
    claims.certificates.every(x=>cfg.certificateDigests.includes(x)) &&
    (claims.playIntegrityVerified!==false||cfg.playIntegrityRequired===false) &&
    typeof claims.key === "string" && !await redis.get("spsec:revoked:"+keyId(claims.key)) &&
    (!cfg.requireHardware || (claims.hardware === true && !!await registeredKey(redis,claims.key,cfg))) &&
    await redis.get("spc2:session:"+claims.jti) === "1";
}
export async function acceptBoundProof(redis,request,op,bytes,bearer,claims,wireBytes=bytes) {
  const nonce=verifyProof(request,op,wireBytes,bearer,claims.key);
  if (!nonce || await redis.set("spc2:proof:"+claims.jti+":"+sha256(nonce),"1",{EX:90,NX:true})!=="OK") return null;
  // Upload frames are never decoding work. Use the existing independent
  // upload quota, preserving per-key, per-session and global abuse controls.
  if (uploads.has(op)) {
    const id=keyId(claims.key),ip=ipKey(request);
    const allowed=await throttle(redis,"spc2:upload:session:"+claims.jti,96,60) &&
      await throttle(redis,"spc2:upload:key-minute:"+id,96,60) &&
      await throttle(redis,"spc2:upload:key-day:"+id,3600,86400) &&
      await throttle(redis,"spc2:upload:ip:"+ip,128,60);
    if(!allowed)return {rateLimited:true};
    if(!await throttle(redis,"spc2:upload:global",256,60))
      throw Object.assign(new Error("Global upload capacity exhausted"),{code:"ENGINE_UNAVAILABLE"});
    return claims;
  }
  // These are normal signed, encrypted requests. They must never consume
  // decoder minute/day budgets, even if a catalog has hundreds of icons or
  // the user has left a long-poll active for many hours.
  if (metadata.has(op)) {
    if(!await throttle(redis,"spc2:metadata:v2:"+claims.jti,1200,60))
      return {rateLimited:true};
    return claims;
  }
  // Job creation/finalization is accounted for separately from decoding.
  // A finished APK analysis must not stop subsequent file decodes.
  if (analysisJobs.has(op)) {
    const id=keyId(claims.key);
    if(!await throttle(redis,"spc2:analysis:v2:"+claims.jti,10,60) ||
       !await throttle(redis,"spc2:analysis:v2:key-day:"+id,1000,86400))
      return {rateLimited:true};
    return claims;
  }
  if(!decodeWork.has(op))return null;
  // Only actual decoder/remote-import operations spend decoding quota.
  if(!await throttle(redis,"spc2:decode:v2:"+claims.jti,30,60) ||
     !await workBudget(redis,claims))
    return {rateLimited:true};
  return claims;
}
export async function authorizeBoundV1(redis,request,bearer,claims,cfg) {
  if (!cfg.configured || !await validBoundClaims(redis,claims,cfg)) return null;
  const url=new URL(request.url), path=url.pathname.slice("/api/v1/".length);
  const op=Number(Object.keys(routes).find(k=>routes[k]===path));
  if (!op || request.method!=="POST" || url.search ||
      request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()!=="application/json" ||
      request.headers.has("content-encoding")) return null;
  const clone=request.clone(), reader=clone.body?.getReader(); if(!reader)return null;
  let size=0;const parts=[];
  try { for(;;){const {done,value}=await reader.read();if(done)break;
    size+=value.length;if(size>bodyLimit(op)){void reader.cancel();return null;}parts.push(Buffer.from(value));
  }} finally {reader.releaseLock();}
  const bytes=Buffer.concat(parts);
  const accepted=await acceptBoundProof(redis,request,op,bytes,bearer,claims);
  if(!accepted || accepted.rateLimited)return accepted;
  return await verifyAction(redis,request,op,bytes,claims,cfg)?accepted:null;
}
