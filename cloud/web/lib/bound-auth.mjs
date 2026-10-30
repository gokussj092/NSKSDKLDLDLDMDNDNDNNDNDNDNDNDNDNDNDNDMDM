import { verifyProof, sha256 } from "./v2-proof.mjs";
import { registeredKey, keyId, workBudget } from "./device-security.mjs";
import { throttle, ipKey } from "./c3-store.mjs";
import { routes, metadata, bodyLimit } from "./v2-routes.mjs";
import { verifyAction } from "./action-integrity.mjs";

export async function validBoundClaims(redis, claims, cfg) {
  return !!claims && !claims.channel && claims.epoch === cfg.epoch &&
    Number.isSafeInteger(claims.versionCode) && claims.versionCode >= cfg.minimumVersionCode &&
    Array.isArray(claims.certificates) && claims.certificates.length > 0 &&
    claims.certificates.every(x=>cfg.certificateDigests.includes(x)) &&
    (claims.playIntegrityVerified!==false||cfg.playIntegrityRequired===false) &&
    typeof claims.key === "string" && !await redis.get("spsec:revoked:"+keyId(claims.key)) &&
    (!cfg.requireHardware || (claims.hardware === true && !!await registeredKey(redis,claims.key,cfg))) &&
    await redis.get("spc2:session:"+claims.jti) === "1";
}
export async function acceptBoundProof(redis,request,op,bytes,bearer,claims) {
  const nonce=verifyProof(request,op,bytes,bearer,claims.key);
  if (!nonce || await redis.set("spc2:proof:"+claims.jti+":"+sha256(nonce),"1",{EX:90,NX:true})!=="OK") return null;
  const lightweight=metadata.has(op), ip=ipKey(request);
  if (!await throttle(redis,"spc2:"+(lightweight?"metadata:":"work:")+claims.jti,lightweight?180:10,60) ||
      (!lightweight && (!await throttle(redis,"spc2:work-ip:"+ip,20,60) || !await workBudget(redis,claims))))
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
