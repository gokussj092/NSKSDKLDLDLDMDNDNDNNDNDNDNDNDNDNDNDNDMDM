/** Phase 4. V2-authenticated, HPKE-protected voluntary feedback.
 * No file uploads, cookies, provider fetches or decoded configuration storage.
 */
import {createHash,randomUUID} from "node:crypto";
import {store,throttle} from "./c3-store.mjs";
import {boundRequestClaims} from "./v2-bound-request.mjs";
const MAX_ITEMS=500,TTL=90*24*3600;
const ISSUE_IDS=new Set(["decode_failed","catalog_download","import_failed","export_failed","app_crash","cloud_access","other"]);
const CATEGORIES=new Set(["method","bug","suggestion"]);
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const plain=s=>typeof s==="string" && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(s);
function publicLink(input){
  if(!plain(input)||input.length<9||input.length>1500)return null;
  try {
    const url=new URL(input);
    if(!["http:","https:"].includes(url.protocol)||url.username||url.password||url.hash)return null;
    const host=url.hostname.toLowerCase();
    if(!host.includes(".") || host.endsWith(".local") ||
       host==="localhost" || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) ||
       host.startsWith("[") || url.port) return null;
    return url.href;
  }catch{return null;}
}
export function validateFeedback(input){
  if(!input||typeof input!=="object"||Array.isArray(input)||
     Object.keys(input).sort().join(",")!=="appBuild,appLink,appVersion,category,description,issues,submissionId" ||
     !CATEGORIES.has(input.category) || !UUID.test(input.submissionId) ||
     !plain(input.appVersion)||!/^\d+\.\d+\.\d+$/.test(input.appVersion)||
     !Number.isInteger(input.appBuild)||input.appBuild<1||input.appBuild>100000 ||
     !plain(input.appLink)||input.appLink.length>1500||
     !plain(input.description)||input.description.length>2000 ||
     !Array.isArray(input.issues)||input.issues.length>ISSUE_IDS.size ||
     input.issues.some(x=>!ISSUE_IDS.has(x))||
     new Set(input.issues).size!==input.issues.length)return null;
  if(input.category==="method"){
    if(!publicLink(input.appLink)||input.description.trim().length<10 ||input.issues.length)return null;
  }else if(input.category==="bug"){
    if(input.appLink||input.issues.length===0)return null; // Description intentionally optional
  }else if(input.appLink||input.issues.length||input.description.trim().length<10)return null;
  return {
    category:input.category,
    appLink:input.category==="method"?publicLink(input.appLink):"",
    description:input.description.trim(),
    issues:input.category==="bug"?input.issues:[],
    appVersion:input.appVersion,appBuild:input.appBuild,
  };
}
const lua=`local old=redis.call('GET',KEYS[1])
if old then return old end
redis.call('SET',KEYS[1],ARGV[1],'EX',ARGV[3])
redis.call('SET',KEYS[3],ARGV[2],'EX',ARGV[3])
redis.call('LPUSH',KEYS[2],ARGV[1])
redis.call('LTRIM',KEYS[2],0,ARGV[4]-1)
redis.call('EXPIRE',KEYS[2],ARGV[3])
return ARGV[1]`;
export async function persistFeedback(redis,claims,body,requestId){
  const keyHash=createHash("sha256").update(claims.key+":"+requestId).digest("hex");
  const idKey="spfeedback:idempotency:"+keyHash;
  const previous=await redis.get(idKey);
  if(previous)return {requestId:previous,duplicate:true};
  const rate=createHash("sha256").update(claims.key).digest("hex");
  if(!await throttle(redis,"spfeedback:hour:"+rate,5,3600))return {rateLimited:true};
  const id=randomUUID();
  const record={id,receivedAt:new Date().toISOString(),...body};
  const accepted=await redis.eval(lua,{
    keys:[idKey,"spfeedback:pending","spfeedback:record:"+id],
    arguments:[id,JSON.stringify(record),String(TTL),String(MAX_ITEMS)]
  });
  return {requestId:accepted,duplicate:accepted!==id};
}
const reply=(body,status)=>Response.json(body,{status,headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
export async function feedbackRequest(request,{storeProvider=store}={}){
  // Called solely by the V2 transport after its HPKE, session, PoP and
  // Play Integrity checks. Direct /api/v1/feedback callers have no binding.
  const claims=boundRequestClaims(request);
  if(!claims?.key || request.method!=="POST")return reply({error:{code:"UNAUTHORIZED"}},401);
  try{
    const raw=await request.text();
    if(Buffer.byteLength(raw,"utf8")>16384)return reply({error:{code:"INPUT_TOO_LARGE"}},413);
    const input=JSON.parse(raw);
    const normalized=validateFeedback(input);
    if(!normalized)return reply({error:{code:"INVALID_REQUEST"}},400);
    const redis=await storeProvider();
    const result=await persistFeedback(redis,claims,normalized,input.submissionId);
    if(result.rateLimited)return reply({error:{code:"RATE_LIMITED"}},429);
    return reply({status:"received",requestId:result.requestId},202);
  }catch{return reply({error:{code:"SERVICE_UNAVAILABLE"}},503);}
}
