/** C9 privacy-minimised diagnostics: NO payloads, file names, IP addresses, credentials or URLs. */
import {createHmac,randomUUID} from "node:crypto";
const PREFIX="spc9:incidents:",INSTALL="spc9:install:";
const RETENTION=8*86400,INSTALL_RETENTION=32*86400;
const SERVICE_IDS=new Set(["files","httpInjector","serverVpn"]);
const KNOWN_FORMAT=/^[a-z0-9][a-z0-9._-]{0,31}$/;
const KNOWN_ERROR=/^[A-Z][A-Z0-9_]{2,49}$/;
const day=(offset=0)=>new Date(Date.now()-offset*86400000).toISOString().slice(0,10);
const bucket=bytes=>Number.isSafeInteger(bytes)&&bytes>=0
  ? bytes===0?"0 B":bytes<=65536?"≤64 KiB":bytes<=1048576?"≤1 MiB":bytes<=8388608?"≤8 MiB":">8 MiB"
  :"No disponible";
export const sizeBucket=bucket;
export function sanitizeDiagnostic({service,format,code,bytes,source,appVersion,severity}={}){
 if(!SERVICE_IDS.has(service))return null;
 const safeFormat=typeof format==="string"&&KNOWN_FORMAT.test(format)?format:"other";
 const safeCode=typeof code==="string"&&KNOWN_ERROR.test(code)?code:"OTHER_ERROR";
 const safeVersion=typeof appVersion==="string"&&/^\d{1,3}(?:\.\d{1,3}){0,3}$/.test(appVersion)?appVersion:"not-provided";
 return {service,format:safeFormat,code:safeCode,sizeBucket:bucket(bytes),
  source:source==="user"?"user":"worker",appVersion:safeVersion,
  severity:severity==="warning"?"warning":"error"};
}
export async function recordIncident(redis,properties){
 const safe=sanitizeDiagnostic(properties);
 if(!safe)return null;
 // Never retain the raw input object or an arbitrary user-generated message.
 const event={id:randomUUID(),at:new Date().toISOString(),...safe};
 const key=PREFIX+day();
 await redis.lPush(key,JSON.stringify(event));
 await redis.lTrim(key,0,149);
 await redis.expire(key,RETENTION);
 return event.id;
}
const NON_INCIDENT=new Set(["PASSWORD_REQUIRED","HWID_REQUIRED","HWID_PASSWORD_REQUIRED",
 "INVALID_CREDENTIALS","AUTH_FAILED","USER_CONSENT_REQUIRED","SERVICE_MAINTENANCE"]);
export async function recordAutomaticIncident(redis,outcome,{kind,format,bytes,errorCode}={}){
 if(!["failed","warning"].includes(outcome)||NON_INCIDENT.has(errorCode))return null;
 const service=kind==="ehi"?"httpInjector":kind==="catalog"||kind==="server-vpn"?"serverVpn":"files";
 return recordIncident(redis,{service,format:kind==="server-vpn"?format:kind==="catalog"?"nur-catalog":kind==="ehi"?"ehi":format||"text",code:errorCode,bytes,source:"worker",severity:outcome==="warning"?"warning":"error"});
}
export async function readIncidents(redis,days=7,baselines={}){
 if(![1,7].includes(days))throw Error("INVALID_RANGE");
 const pages=await Promise.all(Array.from({length:days},(_,i)=>redis.lRange(PREFIX+day(i),0,149)));
 const rows=[];
 for(const page of pages)for(const raw of page){
  try{
   const v=JSON.parse(raw);
   if(!v||typeof v.id!=="string"||!SERVICE_IDS.has(v.service))continue;
   const scope=v.service==="serverVpn"?(v.format==="nur-catalog"?"nur-catalog":"vpn-"+v.format):
     v.service==="httpInjector"?"ehi":v.format;
   if(v.severity!=="warning"&&baselines[scope]?.at&&v.at<=baselines[scope].at)continue;
   rows.push(v);
  }catch{}
 }
 return rows.sort((a,b)=>b.at.localeCompare(a.at)).slice(0,150);
}
export async function recordOptInInstallation(redis,rawId,secret){
 // ID is random per app installation. The server never persists it verbatim.
 if(typeof rawId!=="string"||!/^[0-9a-f]{32}$/.test(rawId))throw Error("INVALID_INSTALL_ID");
 if(typeof secret!=="string"||secret.length<32)throw Error("INVALID_SECRET");
 const derived=createHmac("sha256",secret).update("spdecode-install-v1:"+rawId).digest("hex");
 const key=INSTALL+day();
 await redis.pfAdd(key,derived);
 await redis.expire(key,INSTALL_RETENTION);
}
export async function installationStats(redis){
 const activeDay=await redis.pfCount(INSTALL+day());
 const keys=Array.from({length:30},(_,i)=>INSTALL+day(i));
 const monthly=await redis.pfCount(keys);
 return {activeToday:Math.max(0,Number(activeDay)||0),activeLast30Days:Math.max(0,Number(monthly)||0),
   privacy:"cloud_terms_accepted_approximate_installations",retentionDays:32};
}
