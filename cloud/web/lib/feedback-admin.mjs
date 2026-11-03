/** Phase 5 administrative triage for V2-authenticated voluntary feedback.
 * Records retain the phase-4 90-day TTL, even when an operator changes status.
 */
import {adminSettings,authenticateAdmin,validMutation} from "./c6-admin-auth.mjs";
import {opsStore} from "./c6-ops-store.mjs";
import {jsonReply} from "./responses.mjs";

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const statuses=new Set(["new","reviewing","in_progress","resolved","rejected","archived"]);
const priorities=new Set(["low","normal","high"]);
const categories=new Set(["method","bug","suggestion"]);
const PAGE_SIZE=20,MAX_ITEMS=500;
const key=id=>"spfeedback:record:"+id;
const fail=(code,status)=>jsonReply({status:"error",error:{code}},status,{"Cache-Control":"private, no-store"});
const ok=body=>jsonReply({status:"ok",...body},200,{"Cache-Control":"private, no-store"});
const isRecord=value=>value!==null && typeof value==="object" && !Array.isArray(value);
const statusOf=r=>statuses.has(r.status)?r.status:"new";
const priorityOf=r=>priorities.has(r.priority)?r.priority:"normal";
function safeRecord(r){
  if(!isRecord(r)||!uuid.test(r.id)||!categories.has(r.category)||
    typeof r.description!=="string"||r.description.length>2000||
    typeof r.appLink!=="string"||r.appLink.length>1500||
    !Array.isArray(r.issues)||r.issues.length>7 ||
    typeof r.receivedAt!=="string"||!Number.isFinite(Date.parse(r.receivedAt)))return null;
  const revision=Number.isSafeInteger(r.revision)&&r.revision>=0?r.revision:0;
  return {
    id:r.id,receivedAt:r.receivedAt,category:r.category,
    appLink:r.appLink,description:r.description,issues:r.issues.filter(v=>typeof v==="string"),
    appVersion:typeof r.appVersion==="string"?r.appVersion.slice(0,30):"",
    appBuild:Number.isSafeInteger(r.appBuild)?r.appBuild:0,
    status:statusOf(r),priority:priorityOf(r),
    operatorNote:typeof r.operatorNote==="string"?r.operatorNote.slice(0,600):"",
    updatedAt:typeof r.updatedAt==="string"?r.updatedAt:null,
    revision,
  };
}
export function parseFeedbackFilters(url){
  const input=new URL(url).searchParams;
  if([...input.keys()].some(k=>!["category","status","priority","page"].includes(k)) ||
    [...input.keys()].some(k=>input.getAll(k).length!==1))return null;
  const category=input.get("category")||"all", status=input.get("status")||"all";
  const priority=input.get("priority")||"all",pageValue=input.get("page")||"0";
  if((category!=="all"&&!categories.has(category))||
     (status!=="all"&&!statuses.has(status))||
     (priority!=="all"&&!priorities.has(priority))||
     !/^(0|[1-9][0-9]?)$/.test(pageValue)||Number(pageValue)>24)return null;
  return {category,status,priority,page:Number(pageValue)};
}
export async function listFeedback(redis,filters){
  const rawIds=await redis.lRange("spfeedback:pending",0,MAX_ITEMS-1);
  const ids=[...new Set(rawIds.filter(id=>typeof id==="string"&&uuid.test(id)))];
  const raw=ids.length?await redis.mGet(ids.map(key)):[];
  const available=[];
  for(let i=0;i<ids.length;i++){
    try{
      if(!raw[i])continue;
      const item=safeRecord(JSON.parse(raw[i]));
      if(item&&item.id===ids[i])available.push(item);
    }catch{/* Old or expired items cannot disrupt triage. */}
  }
  const totals={
    available:available.length,
    new:available.filter(x=>x.status==="new").length,
    reviewing:available.filter(x=>x.status==="reviewing").length,
    in_progress:available.filter(x=>x.status==="in_progress").length,
    resolved:available.filter(x=>x.status==="resolved").length,
    rejected:available.filter(x=>x.status==="rejected").length,
    archived:available.filter(x=>x.status==="archived").length,
    method:available.filter(x=>x.category==="method").length,
    bug:available.filter(x=>x.category==="bug").length,
    suggestion:available.filter(x=>x.category==="suggestion").length,
  };
  const filtered=available.filter(x=>
    (filters.category==="all"||x.category===filters.category)&&
    (filters.status==="all"||x.status===filters.status)&&
    (filters.priority==="all"||x.priority===filters.priority));
  const offset=filters.page*PAGE_SIZE;
  return {items:filtered.slice(offset,offset+PAGE_SIZE),page:filters.page,pageSize:PAGE_SIZE,
    total:filtered.length,pages:Math.ceil(filtered.length/PAGE_SIZE),totals};
}
export function validateFeedbackUpdate(body){
  if(!isRecord(body)||Object.keys(body).sort().join(",")!=="expectedRevision,id,note,priority,status" ||
    !uuid.test(body.id)||!statuses.has(body.status)||!priorities.has(body.priority)||
    !Number.isSafeInteger(body.expectedRevision)||body.expectedRevision<0||
    body.expectedRevision>100000 || typeof body.note!=="string"||body.note.length>600||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(body.note))return null;
  return {...body,note:body.note.trim()};
}
// Atomic compare-and-set, retains original TTL (Redis >=6).
const mutation=[
  "local original=redis.call('GET',KEYS[1])",
  "if not original then return {0} end",
  "local record=cjson.decode(original)",
  "local current=tonumber(record.revision or 0)",
  "if current~=tonumber(ARGV[1]) then return {1} end",
  "record.status=ARGV[2]",
  "record.priority=ARGV[3]",
  "record.operatorNote=ARGV[4]",
  "record.updatedAt=ARGV[5]",
  "record.revision=current+1",
  "redis.call('SET',KEYS[1],cjson.encode(record),'KEEPTTL')",
  "return {2,cjson.encode(record)}",
].join("\n");
export async function updateFeedback(redis,input){
  const updated=await redis.eval(mutation,{
    keys:[key(input.id)],
    arguments:[String(input.expectedRevision),input.status,input.priority,input.note,new Date().toISOString()],
  });
  if(!Array.isArray(updated)||!Number.isInteger(updated[0]))throw Error("STORAGE_UNAVAILABLE");
  if(updated[0]===0)return {error:"NOT_FOUND",status:404};
  if(updated[0]===1)return {error:"REVISION_CONFLICT",status:409};
  const record=safeRecord(JSON.parse(updated[1]));
  if(!record||record.revision!==input.expectedRevision+1)throw Error("STORAGE_UNAVAILABLE");
  return {record};
}
async function readMutation(request,limit=4096){
  if(request.headers.get("content-type")?.split(";")[0]?.trim()!=="application/json" ||
    request.headers.has("content-encoding")||!request.body)return null;
  const size=request.headers.get("content-length");
  if(size&&(!/^\d+$/.test(size)||Number(size)>limit))return null;
  const reader=request.body.getReader(),chunks=[];let total=0;
  try{
    for(;;){
      const {done,value}=await reader.read();if(done)break;
      total+=value.byteLength;
      if(total>limit){await reader.cancel();return null;}
      chunks.push(value);
    }
    return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks)));
  }catch{return null;}finally{reader.releaseLock();}
}
export async function feedbackAdminRequest(request,options={}){
  const cfg=(options.settingsProvider||adminSettings)();
  if(!cfg.enabled)return fail("ADMIN_DISABLED",503);
  if(!["GET","POST"].includes(request.method))return fail("METHOD_NOT_ALLOWED",405);
  if(request.method==="POST"&&!validMutation(request,cfg))return fail("CSRF_REJECTED",403);
  try{
    const redis=await (options.storeProvider||opsStore)();
    if(!await (options.authenticate||authenticateAdmin)(redis,request,cfg))return fail("UNAUTHORIZED",401);
    if(request.method==="GET"){
      const filters=parseFeedbackFilters(request.url);
      if(!filters)return fail("INVALID_REQUEST",400);
      return ok({feedback:await listFeedback(redis,filters)});
    }
    const body=validateFeedbackUpdate(await readMutation(request));
    if(!body)return fail("INVALID_REQUEST",400);
    const result=await updateFeedback(redis,body);
    return result.error?fail(result.error,result.status):ok({record:result.record});
  }catch{return fail("SERVICE_UNAVAILABLE",503);}
}
