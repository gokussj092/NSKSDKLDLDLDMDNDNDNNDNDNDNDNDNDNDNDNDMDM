import { denyAccessRisk } from "./rasp-policy.mjs";
import { randomUUID,randomBytes,createHash } from "node:crypto";
import { decodePlayToken,checkIntegrityVerdict } from "./c3-integrity.mjs";
import { sha256 } from "./v2-proof.mjs";
export const protectedActions=new Set([4,5,6,7,8,9,12]);
export function inlineActionHash(bearer,op,bodySha256,id){
 if(typeof bearer!=="string"||bearer.length>2048||!protectedActions.has(op)||
  !/^[a-f0-9]{64}$/.test(bodySha256)||!/^i2\.[A-Za-z0-9_-]{32}$/.test(id))return null;
 return createHash("sha256").update(["SPDECODE-ACTION-V2",bearer,String(op),bodySha256,id.slice(3)].join("\n")).digest("base64url");
}
export async function actionChallenge(redis,claims,body,cfg) {
  if(!body || Object.keys(body).sort().join(",")!=="bodySha256,operation" ||
      !protectedActions.has(body.operation) || !/^[a-f0-9]{64}$/.test(body.bodySha256)) return null;
  const id=randomUUID(),nonce=randomBytes(32).toString("base64url");
  const requestHash=createHash("sha256").update(["SPDECODE-ACTION-V1",claims.jti,
    sha256(claims.key),String(body.operation),body.bodySha256,id,nonce].join("\n")).digest("base64url");
  const value={jti:claims.jti,operation:body.operation,bodySha256:body.bodySha256,requestHash,created:Date.now()};
  if(await redis.set("spsec:action:"+id,JSON.stringify(value),{EX:120,NX:true})!=="OK")throw Error("ACTION_UNAVAILABLE");
  return {challengeId:id,requestHash,cloudProjectNumber:cfg.cloudProjectNumber,expiresIn:120};
}
export async function verifyAction(redis,request,op,bytes,claims,cfg,{decodeIntegrity=decodePlayToken}={}) {
  if(!cfg.requireAction || !protectedActions.has(op))return true;
  const id=request.headers.get("x-sp-action-challenge")||"", token=request.headers.get("x-sp-action-integrity")||"";
  if(/^i2\.[A-Za-z0-9_-]{32}$/.test(id)){
    if(token.length<80||token.length>16384)return false;
    const bearer=(request.headers.get("authorization")||"").slice(7);
    const requestHash=inlineActionHash(bearer,op,sha256(bytes),id);
    if(!requestHash)return false;
    // The surrounding transport already consumed the signed, per-request PoP nonce.
    // The token is additionally bound to this server-issued bearer and exact ciphertext.
    if(await redis.set("spsec:action-used:"+claims.jti+":"+id,"1",{EX:150,NX:true})!=="OK")return false;
    const verdict=await decodeIntegrity(token,cfg);
    return checkIntegrityVerdict(verdict,{...cfg,requestHash})&&
      !denyAccessRisk(verdict,cfg,claims.versionCode);
  }
  if(!/^[0-9a-f-]{36}$/.test(id) || token.length<80 || token.length>16384)return false;
  const raw=await redis.getDel("spsec:action:"+id);if(!raw)return false;
  const value=JSON.parse(raw);
  if(value.jti!==claims.jti || value.operation!==op || value.bodySha256!==sha256(bytes) ||
     Date.now()-value.created>120000 || value.created>Date.now()+5000)return false;
  const verdict=await decodeIntegrity(token,cfg);
  return checkIntegrityVerdict(verdict,{...cfg,requestHash:value.requestHash}) &&
    !denyAccessRisk(verdict,cfg,claims.versionCode);
}
