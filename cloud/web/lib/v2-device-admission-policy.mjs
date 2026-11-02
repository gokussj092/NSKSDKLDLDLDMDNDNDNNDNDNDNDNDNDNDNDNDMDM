/** Device posture is independent of certificate authenticity. Permanent compatible defaults. */
import {readFile,stat} from "node:fs/promises";
import {join} from "node:path";
import {withFileLock,atomicJson} from "./durable-json.mjs";
export const PATCH_MONTHS=Object.freeze([12,18,24,36,48]);
export const TEST_HOURS=Object.freeze([0,1,6,24,48]);
export const MAX_TEST_MS=48*60*60*1000;
const ROOT=process.env.CLOUD_V2_POLICY_ROOT||"/app/provider-control",FILE="v2-device-admission.json";
const defaults=()=>({version:2,patchMonths:24,enforcePatch:false,enforceBoot:false,expiresAt:0,revision:0});
function validate(x){
 if(!x||typeof x!=="object"||Array.isArray(x)||
  Object.keys(x).sort().join(",")!=="enforceBoot,enforcePatch,expiresAt,patchMonths,revision,version"||
  ![1,2].includes(x.version)||!PATCH_MONTHS.includes(x.patchMonths)||
  typeof x.enforcePatch!=="boolean"||typeof x.enforceBoot!=="boolean"||
  !Number.isSafeInteger(x.revision)||x.revision<0||
  !Number.isSafeInteger(x.expiresAt)||x.expiresAt<0)throw Error("V2_DEVICE_POLICY_INVALID");
 return x;
}
async function read(root){
 let raw;try{raw=await readFile(join(root,FILE),"utf8");}
 catch(e){if(e.code==="ENOENT")return null;throw Error("V2_DEVICE_POLICY_UNAVAILABLE");}
 if(Buffer.byteLength(raw)>1024)throw Error("V2_DEVICE_POLICY_INVALID");
 try{return validate(JSON.parse(raw));}catch{throw Error("V2_DEVICE_POLICY_INVALID");}
}
export async function loadV2DevicePolicy(options={}){
 const root=options.root||ROOT;
 try{if(!(await stat(root)).isDirectory())throw Error("NOT_DIRECTORY");}
 catch(e){if(e.code==="ENOENT"&&!options.root&&process.env.NODE_ENV!=="production")return defaults();
  throw Error("V2_DEVICE_POLICY_UNAVAILABLE");}
 const saved=await read(root);if(saved?.version===2)return saved;
 return withFileLock(root,"v2-device-policy",async()=>{
  const current=await read(root);if(current?.version===2)return current;
  const next={...defaults(),revision:current?current.revision+1:0};
  await atomicJson(root,FILE,next);return next;
 });
}
export async function v2DevicePolicyStatus(options={}){
 const saved=await loadV2DevicePolicy(options),now=options.now??Date.now();
 const active=saved.expiresAt===0||(saved.expiresAt>now&&saved.expiresAt<=now+MAX_TEST_MS);
 const effective=active?saved:defaults();
 return {patchMonths:effective.patchMonths,enforcePatch:effective.enforcePatch,
  enforceBoot:effective.enforceBoot,expiresAt:active&&saved.expiresAt?new Date(saved.expiresAt).toISOString():null,
  permanent:saved.expiresAt===0,expired:!active,
  relaxed:!effective.enforcePatch||!effective.enforceBoot||effective.patchMonths!==12,
  revision:saved.revision,rootDetection:"unknown-not-detectable-via-key-attestation"};
}
export async function changeV2DevicePolicy({patchMonths,enforcePatch,enforceBoot,durationHours,expectedRevision},options={}){
 if(!PATCH_MONTHS.includes(patchMonths)||typeof enforcePatch!=="boolean"||typeof enforceBoot!=="boolean"||
  !TEST_HOURS.includes(durationHours)||!Number.isSafeInteger(expectedRevision)||expectedRevision<0)
  throw Error("V2_DEVICE_POLICY_INVALID");
 const root=options.root||ROOT,now=options.now??Date.now();
 if(!Number.isSafeInteger(now)||now<=0)throw Error("V2_DEVICE_POLICY_INVALID");
 await loadV2DevicePolicy(options);
 return withFileLock(root,"v2-device-policy",async()=>{
  const previous=await read(root);
  if(previous.revision!==expectedRevision)throw Error("V2_DEVICE_POLICY_CONFLICT");
  const next=validate({version:2,patchMonths,enforcePatch,enforceBoot,
   expiresAt:durationHours?now+durationHours*3600000:0,revision:previous.revision+1});
  await atomicJson(root,FILE,next);
  return {patchMonths,enforcePatch,enforceBoot,expiresAt:next.expiresAt?new Date(next.expiresAt).toISOString():null,
   permanent:!durationHours,expired:false,relaxed:!enforcePatch||!enforceBoot||patchMonths!==12,
   revision:next.revision,rootDetection:"unknown-not-detectable-via-key-attestation"};
 });
}
