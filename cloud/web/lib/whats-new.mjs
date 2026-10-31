/** Server-controlled What's New. No HTML, links, credentials or decoder details. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {boundRequestClaims} from "./v2-bound-request.mjs";

const MAX_JSON=16384,MAX_ITEMS=12;
const languages=new Set(["en","es","ar","fa","fr","id","ru","de","pt-BR",
  "tr","vi","hi","ja","it"]);
const formats=new Set(["feature","support","improvement","fix"]);
// Line breaks are supported only in item descriptions, for readable lists.
// Reject every other control character, HTML delimiters and long text.
const safeText=(value,max,allowLines=false)=>typeof value==="string"&&value.length>0&&value.length<=max
  && [...value].every(char=>char!=="<"&&char!==">"&&
    (char.charCodeAt(0)>=32 || (allowLines&&char==="\n")));
function validLocalized(value,max,allowLines=false){
 return value&&typeof value==="object"&&!Array.isArray(value)&&
  Object.keys(value).length>0&&Object.keys(value).every(x=>languages.has(x))&&
  safeText(value.en,max,allowLines)&&
  Object.values(value).every(x=>safeText(x,max,allowLines));
}
export function validateNews(input){
 if(!input||typeof input!=="object"||Array.isArray(input)||
    !Number.isSafeInteger(input.version)||input.version<1||input.version>999999999||
    input.schemaVersion!==1||!/^\d{4}-\d{2}-\d{2}$/.test(input.publishedAt||"")||
    !validLocalized(input.title,100)||!validLocalized(input.subtitle,250)||
    !Array.isArray(input.items)||input.items.length<1||input.items.length>MAX_ITEMS)
  throw Error("INVALID_RELEASE_NOTES");
 const ids=new Set();
 for(const entry of input.items){
  if(!entry||typeof entry!=="object"||!/^[-a-z0-9]{3,48}$/.test(entry.id||"")||
     ids.has(entry.id)||!formats.has(entry.type)||!validLocalized(entry.title,90)||
     !validLocalized(entry.description,320,true))throw Error("INVALID_RELEASE_NOTES");
  ids.add(entry.id);
 }
 return input;
}
/** Existing V2 editorial publication. Its version, payload and overrides stay intact. */
export function loadNews(env=process.env){
 const raw=env.CLOUD_WHATS_NEW_JSON||
  readFileSync(join(process.cwd(),"content","whats-new.json"),"utf8");
 if(Buffer.byteLength(raw,"utf8")>MAX_JSON)throw Error("INVALID_RELEASE_NOTES");
 return validateNews(JSON.parse(raw));
}
/** Separate V1 publication; never used by authenticated V2 transport requests. */
export function loadV1News(env=process.env){
 const raw=env.CLOUD_WHATS_NEW_V1_JSON||
  readFileSync(join(process.cwd(),"content","whats-new-v1.json"),"utf8");
 if(Buffer.byteLength(raw,"utf8")>MAX_JSON)throw Error("INVALID_RELEASE_NOTES");
 return validateNews(JSON.parse(raw));
}
export function localizeNews(content,locale){
 const language=languages.has(locale)?locale:"en";
 const localized=v=>v[language]||v.en;
 return {apiVersion:"v1",version:content.version,locale:language,
  publishedAt:content.publishedAt,title:localized(content.title),
  subtitle:localized(content.subtitle),
  items:content.items.map(x=>({id:x.id,type:x.type,title:localized(x.title),
   description:localized(x.description)}))};
}
/** Optional operator-published Android update hint. Never return arbitrary URLs.
 * A code of zero disables it; public release requires a separate owner action.
 */
export function androidUpdateHint(env=process.env){
 const raw=env.CLOUD_ANDROID_LATEST_VERSION_CODE||"0";
 if(!/^(0|[1-9][0-9]{0,8})$/.test(raw))throw Error("INVALID_APP_UPDATE");
 const code=Number(raw);
 if(code===0)return null;
 const version=env.CLOUD_ANDROID_LATEST_VERSION_NAME||"";
 if(!/^\d+\.\d+\.\d+$/.test(version))throw Error("INVALID_APP_UPDATE");
 return {versionCode:code,versionName:version};
}

export const RECHECK_AFTER=1800;
export async function whatsNewRequest(request,{source=loadV1News,v2Source=loadNews}={}){
 const json=(payload,status=200)=>Response.json(payload,{status,
  headers:{"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
 let input;
 try{
  if(request.method!=="POST"||
   request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase()!=="application/json"||
   Number(request.headers.get("content-length")||0)>512)return json({error:{code:"INVALID_REQUEST"}},400);
  input=await request.json();
  if(!input||typeof input!=="object"||Array.isArray(input)||
   Object.keys(input).some(k=>!["knownVersion","locale"].includes(k))||
   !Number.isSafeInteger(input.knownVersion)||input.knownVersion<0||input.knownVersion>999999999||
   typeof input.locale!=="string"||input.locale.length>16)
   return json({error:{code:"INVALID_REQUEST"}},400);
 }catch{return json({error:{code:"INVALID_REQUEST"}},400);}
 try{
  // V2 internally dispatches operation 14 to the legacy route, but binds
  // verified claims to the exact in-memory Request (never to user headers).
  // V1-only update notices MUST NOT leak into V2 through this shared handler.
  const contents=boundRequestClaims(request)?v2Source():source();
  const head={apiVersion:"v1",version:contents.version,
   recheckAfterSeconds:RECHECK_AFTER,...(androidUpdateHint()?{appUpdate:androidUpdateHint()}:{})};
  if(contents.version<=input.knownVersion)return json({...head,unchanged:true});
  return json({...head,unchanged:false,...localizeNews(contents,input.locale)});
 }catch{return json({error:{code:"SERVICE_UNAVAILABLE"}},503);}
}
