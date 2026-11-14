/** Backend-only source inventory for the owner's 2026-11-14 application batches. */
import {readFileSync,existsSync} from "node:fs";
import {join} from "node:path";
import {randomBytes,randomUUID} from "node:crypto";
import {DEFAULT_DTUNNEL_REQUEST_ID} from "./dtunnel-credentials.server.mjs";

const deployed=join(process.cwd(),"content/supplied-integrations.json");
const source=existsSync(deployed)?deployed:new URL("../content/supplied-integrations.json",import.meta.url);
const document=JSON.parse(readFileSync(source,"utf8"));
if(document.schemaVersion!==1||document.apps.length!==57||
   new Set(document.apps.map(x=>x.id)).size!==57)throw Error("INTEGRATION_INVENTORY_INVALID");
export const SUPPLIED_INTEGRATIONS=Object.freeze(document.apps.map(x=>Object.freeze(x)));
const byId=new Map(SUPPLIED_INTEGRATIONS.map(x=>[x.id,x]));
export const SUPPLIED_CATALOG_ITEMS=Object.freeze(SUPPLIED_INTEGRATIONS
 .filter(x=>x.requests.length||x.existingBroker)
 .map(x=>Object.freeze({id:x.id,name:x.name,icon:x.icon,remote:x.id})));
export const suppliedProviderIds=()=>SUPPLIED_INTEGRATIONS.filter(x=>x.requests.length).map(x=>x.id);
function credential(id,request,env){
 const value=env[request.secretHeader.env];
 if(value!==undefined&&value!=="")return value;
 return id==="dtunnel-mod"?DEFAULT_DTUNNEL_REQUEST_ID:undefined;
}
export function suppliedProviderConfigured(id,env=process.env){
 const item=byId.get(id);if(!item?.requests.length)return false;
 return item.requests.every(r=>!r.secretHeader||
  (typeof credential(id,r,env)==="string"&&/^[\x21-\x7e]{1,512}$/.test(credential(id,r,env))));
}
export function suppliedRequests(id,env=process.env){
 const item=byId.get(id);if(!item?.requests.length)throw Error("UNSUPPORTED_FORMAT");
 if(!suppliedProviderConfigured(id,env))throw Error("REMOTE_NOT_CONFIGURED");
 return item.requests.map(r=>{
  const headers={...r.headers};
  if(r.secretHeader)headers[r.secretHeader.header]=credential(id,r,env);
  if(r.sessionHeaders)Object.assign(headers,{"X-App-Device":randomUUID().replaceAll("-",""),
   "X-App-Ts":String(Math.floor(Date.now()/1000)),"X-App-Nonce":randomBytes(8).toString("hex")});
  return {name:r.name,url:r.url,agent:r.agent,headers,method:r.method,body:r.body?Buffer.from(r.body):null};
 });
}
export function packSuppliedCatalog(id,sources){
 const item=byId.get(id);
 if(!item||Object.keys(sources).length!==item.requests.length||
    item.requests.some(r=>!Buffer.isBuffer(sources[r.name])||!sources[r.name].length))
  throw Error("REMOTE_RESPONSE_INVALID");
 if(item.requests.length===1)return sources[item.requests[0].name];
 const bytes=Buffer.from(JSON.stringify({kind:"spdecode-supplied-catalog-v1",providerId:id,
  sources:Object.fromEntries(item.requests.map(r=>[r.name,sources[r.name].toString("base64")]))}));
 if(bytes.length>8*1024*1024)throw Error("REMOTE_TOO_LARGE");
 return bytes;
}
