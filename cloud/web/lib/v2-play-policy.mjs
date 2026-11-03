/** Persistent V2 Play policy. Device signals can be observed without denying access.
 * Google certificates, app identity, request proofs and hardware enrollment are independent. */
import {readFile,stat} from "node:fs/promises";
import {join} from "node:path";
import {withFileLock,atomicJson} from "./durable-json.mjs";
export const MAX_V2_BETA_MS=15*24*60*60*1000; // legacy API compatibility only
export const PLAY_MODES=Object.freeze(["observe","enforce","off"]);
export const DEVICE_LEVELS=Object.freeze(["observe","basic","device","strong"]);
const ROOT=process.env.CLOUD_V2_POLICY_ROOT||"/app/provider-control";
const FILE="v2-play-integrity.json";
const fields=["mode","deviceIntegrity","requireLicensed","requireSdk","minimumDeviceSdk",
 "requirePlayProtect","requireAccessRisk","requireAction","sessionSeconds"];
export const compatiblePlayDefaults=()=>({version:2,mode:"observe",deviceIntegrity:"observe",
 requireLicensed:false,requireSdk:false,minimumDeviceSdk:24,requirePlayProtect:false,
 requireAccessRisk:false,requireAction:false,sessionSeconds:1800,revision:0});
function valid(p){
 if(!p||typeof p!=="object"||Array.isArray(p)||
  Object.keys(p).sort().join(",")!==["version","revision",...fields].sort().join(",")||
  p.version!==2||!PLAY_MODES.includes(p.mode)||!DEVICE_LEVELS.includes(p.deviceIntegrity)||
  ["requireLicensed","requireSdk","requirePlayProtect","requireAccessRisk","requireAction"].some(k=>typeof p[k]!=="boolean")||
  !Number.isSafeInteger(p.minimumDeviceSdk)||p.minimumDeviceSdk<24||p.minimumDeviceSdk>100||
  ![300,900,1800,3600].includes(p.sessionSeconds)||
  !Number.isSafeInteger(p.revision)||p.revision<0)throw Error("V2_PLAY_POLICY_INVALID");
 return p;
}
async function read(root){
 let raw;try{raw=await readFile(join(root,FILE),"utf8");}
 catch(e){if(e.code==="ENOENT")return null;throw Error("V2_PLAY_POLICY_UNAVAILABLE");}
 if(Buffer.byteLength(raw)>4096)throw Error("V2_PLAY_POLICY_INVALID");
 let p;try{p=JSON.parse(raw);}catch{throw Error("V2_PLAY_POLICY_INVALID");}
 if(p?.version===1){
  if(typeof p.integrityRequired!=="boolean"||!Number.isSafeInteger(p.betaUntil)||p.betaUntil<0||
   !Number.isSafeInteger(p.revision)||p.revision<0||
   Object.keys(p).sort().join(",")!=="betaUntil,integrityRequired,revision,version")
   throw Error("V2_PLAY_POLICY_INVALID");
  // Explicit one-time compatibility migration requested by the owner.
  return {policy:{...compatiblePlayDefaults(),revision:p.revision+1},migrate:true};
 }
 return {policy:valid(p),migrate:false};
}
export async function loadV2PlayPolicy(options={}){
 const root=options.root||ROOT;
 try{if(!(await stat(root)).isDirectory())throw Error("NOT_DIRECTORY");}
 catch(e){if(e.code==="ENOENT"&&!options.root&&process.env.NODE_ENV!=="production")return compatiblePlayDefaults();
  throw Error("V2_PLAY_POLICY_UNAVAILABLE");}
 const saved=await read(root);if(saved&&!saved.migrate)return saved.policy;
 return withFileLock(root,"v2-play-policy",async()=>{
  const current=await read(root);
  if(current&&!current.migrate)return current.policy;
  const value=current?.policy||compatiblePlayDefaults();
  await atomicJson(root,FILE,value);return value;
 });
}
export async function v2PlayPolicyStatus(options={}){
 const p=await loadV2PlayPolicy(options);
 return {...p,integrityRequired:p.mode==="enforce",integrityRequested:p.mode!=="off",
  betaUntil:null,permanent:true};
}
export async function changeV2PlaySettings(settings,expectedRevision,options={}){
 if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0||
  !settings||Object.keys(settings).sort().join(",")!==fields.slice().sort().join(","))
  throw Error("V2_PLAY_POLICY_INVALID");
 const root=options.root||ROOT;
 await loadV2PlayPolicy(options);
 return withFileLock(root,"v2-play-policy",async()=>{
  const current=(await read(root)).policy;
  if(current.revision!==expectedRevision)throw Error("V2_PLAY_POLICY_CONFLICT");
  const next=valid({version:2,...settings,revision:current.revision+1});
  await atomicJson(root,FILE,next);
  return {...next,integrityRequired:next.mode==="enforce",integrityRequested:next.mode!=="off",
   betaUntil:null,permanent:true};
 });
}
export async function changeV2PlayPolicy(integrityRequired,expectedRevision,options={}){
 if(typeof integrityRequired!=="boolean")throw Error("V2_PLAY_POLICY_INVALID");
 const current=await loadV2PlayPolicy(options);
 const next=Object.fromEntries(fields.map(k=>[k,current[k]]));
 next.mode=integrityRequired?"enforce":"observe";
 return changeV2PlaySettings(next,expectedRevision,options);
}
