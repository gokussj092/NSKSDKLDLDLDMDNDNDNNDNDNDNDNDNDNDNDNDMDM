/**
 * F7 APK QA gateway. Requests arrive ONLY from the existing V2 verified
 * HPKE + PoP + Integrity tunnel. No public V1 or unauthenticated side door.
 * This is a temporary 0-credit owner's QA path, not commercial billing.
 */
import {createHash} from "node:crypto";
import {boundRequestClaims} from "./v2-bound-request.mjs";
import {jsonReply} from "./responses.mjs";
const METHODS=Object.freeze({21:"start",22:"chunk",23:"finish",24:"result"});
const MAX_BODY=3*1024*1024;

const reply=(code,status)=>jsonReply({error:{code}},status);
function settings(env=process.env){
  const key=env.CLOUD_APK_QA_INTERNAL_TOKEN||"";
  // QA owner testing is opt-in on the VPS. No manual device registration:
  // only the existing authenticated V2 HPKE/PoP/Integrity path is trusted.
  // The internal web-to-lab credential is auto-provisioned by spdecode apk-qa enable.
  return {enabled:env.CLOUD_APK_QA_ENABLED==="true" &&
    typeof key==="string" && key.length>=32,
    key,endpoint:"http://apk-qa:8792"};
}
async function readJSON(request,limit){
  if(request.headers.get("content-type")?.split(";")[0]?.trim()!=="application/json"
     || !request.body || request.headers.has("content-encoding"))
    throw Error("INVALID_REQUEST");
  const len=Number(request.headers.get("content-length"));
  if(Number.isFinite(len) && len>limit)throw Error("INPUT_TOO_LARGE");
  const reader=request.body.getReader(),chunks=[];let size=0;
  try{
    while(true){const {done,value}=await reader.read();if(done)break;
      size+=value.length;if(size>limit)throw Error("INPUT_TOO_LARGE");
      chunks.push(value);}
  }finally{reader.releaseLock();}
  const obj=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));
  if(!obj||typeof obj!=="object"||Array.isArray(obj))throw Error("INVALID_REQUEST");
  return obj;
}
export async function apkQaRequest(request,operation,{env=process.env,send=fetch}={}){
  const action=METHODS[operation],cfg=settings(env);
  if(!action)return reply("INVALID_REQUEST",400);
  // Only trusted internal dispatch can set these WeakMap claims; caller headers
  // cannot forge them. Require HPKE so capability tokens never travel in clear.
  const claims=boundRequestClaims(request);
  if(!claims || claims.hpke!==true || typeof claims.key!=="string" ||
     claims.key.length<32 || claims.scope!=="decode")return reply("UNAUTHORIZED",401);
  if(!cfg.enabled)return reply("APK_QA_DISABLED",503);
  if(request.method!=="POST")return reply("INVALID_REQUEST",405);
  let payload;
  try{
    payload=await readJSON(request,operation===22?MAX_BODY:4096);
  }catch(e){
    return reply(e?.message==="INPUT_TOO_LARGE"?"INPUT_TOO_LARGE":"INVALID_REQUEST",
      e?.message==="INPUT_TOO_LARGE"?413:400);
  }
  if(operation===21){
    // No user account or credits required for this opt-in QA.
    if(payload.consent!==true || payload.qaFirstPass!==true)
      return reply("CONSENT_REQUIRED",403);
  }
  const owner=createHash("sha256").update(claims.key,"utf8").digest("hex");
  // No operator-entered device ID or allowlist. The verified public signing
  // key binds each upload automatically so reconnects cannot cross owners.
  // Never trust the owner hash from the external payload.
  delete payload.deviceKeyHash;
  payload.deviceKeyHash=owner;
  try{
    const response=await send(cfg.endpoint+"/internal/qa/"+action,{
      method:"POST",
      headers:{"content-type":"application/json","x-sp-apk-internal":cfg.key},
      body:JSON.stringify(payload),
      signal:AbortSignal.timeout(12000),
      cache:"no-store",
    });
    if(!Number.isInteger(response.status)||response.status<200||response.status>599)
      throw Error("INVALID_INTERNAL_RESPONSE");
    const type=response.headers.get("content-type")?.split(";")[0]?.trim();
    if(type!=="application/json")throw Error("INVALID_INTERNAL_RESPONSE");
    const content=await response.text();
    if(content.length>128*1024)throw Error("INVALID_INTERNAL_RESPONSE");
    const value=JSON.parse(content);
    if(!value||typeof value!=="object"||Array.isArray(value))
      throw Error("INVALID_INTERNAL_RESPONSE");
    if(!response.ok){
      const code=value.error;
      if(!/^[A-Z_]{3,40}$/.test(code||""))return reply("APK_QA_UNAVAILABLE",503);
      return reply(code,response.status);
    }
    // All user data and result are returned exclusively inside V2's
    // encrypted response envelope; never log payload/report/uploadToken.
    return jsonReply(value,response.status);
  }catch{
    return reply("APK_QA_UNAVAILABLE",503);
  }
}
