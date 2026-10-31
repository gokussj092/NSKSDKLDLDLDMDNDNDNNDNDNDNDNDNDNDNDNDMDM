/** API V2 experimental device compatibility. Only cryptographically verified
 * hardware attestation may reach these optional policy gates.
 * Relaxations are short-lived and automatically fall back to strict defaults.
 * No root status can be inferred reliably from Android hardware attestation.
 */
import {readFile,stat} from "node:fs/promises";
import {join} from "node:path";
import {withFileLock,atomicJson} from "./durable-json.mjs";
export const PATCH_MONTHS=Object.freeze([12,18,24,36,48]);
export const TEST_HOURS=Object.freeze([1,6,24,48]);
export const MAX_TEST_MS=48*60*60*1000;
const ROOT=process.env.CLOUD_V2_POLICY_ROOT||"/app/provider-control";
const FILE="v2-device-admission.json";
const defaults=()=>({version:1,patchMonths:12,enforcePatch:true,enforceBoot:true,expiresAt:0,revision:0});
const relaxed=x=>x.patchMonths!==12||!x.enforcePatch||!x.enforceBoot;
function validate(x){
 if(!x||typeof x!=="object"||Array.isArray(x)||
  Object.keys(x).sort().join(",")!=="enforceBoot,enforcePatch,expiresAt,patchMonths,revision,version"||
  x.version!==1||!PATCH_MONTHS.includes(x.patchMonths)||
  typeof x.enforcePatch!=="boolean"||typeof x.enforceBoot!=="boolean"||
  !Number.isSafeInteger(x.revision)||x.revision<0||
  !Number.isSafeInteger(x.expiresAt)||x.expiresAt<0||
  (relaxed(x)!==(x.expiresAt>0)))
  throw Error("V2_DEVICE_POLICY_INVALID");
 return x;
}
async function read(root){
 let raw;
 try{raw=await readFile(join(root,FILE),"utf8");}
 catch(e){if(e.code==="ENOENT")return null;throw Error("V2_DEVICE_POLICY_UNAVAILABLE");}
 if(Buffer.byteLength(raw,"utf8")>1024)throw Error("V2_DEVICE_POLICY_INVALID");
 try{return validate(JSON.parse(raw));}catch{throw Error("V2_DEVICE_POLICY_INVALID");}
}
export async function loadV2DevicePolicy(options={}){
 const root=options.root||ROOT;
 try{if(!(await stat(root)).isDirectory())throw Error("NOT_DIRECTORY");}
 catch(e){
  if(e.code==="ENOENT"&&!options.root&&process.env.NODE_ENV!=="production")return defaults();
  throw Error("V2_DEVICE_POLICY_UNAVAILABLE");
 }
 return (await read(root))||defaults();
}
/** Query-time enforcement; no cron or container restarts required after admin changes. */
export async function v2DevicePolicyStatus(options={}){
 const saved=await loadV2DevicePolicy(options),now=options.now??Date.now();
 const active=relaxed(saved)&&saved.expiresAt>now&&saved.expiresAt<=now+MAX_TEST_MS;
 return {patchMonths:active?saved.patchMonths:12,
  enforcePatch:active?saved.enforcePatch:true,
  enforceBoot:active?saved.enforceBoot:true,
  expiresAt:active?new Date(saved.expiresAt).toISOString():null,
  relaxed:active,revision:saved.revision,
  rootDetection:"not-available-via-key-attestation"};
}
export async function changeV2DevicePolicy({patchMonths,enforcePatch,enforceBoot,durationHours,expectedRevision},options={}){
 if(!PATCH_MONTHS.includes(patchMonths)||
   typeof enforcePatch!=="boolean"||typeof enforceBoot!=="boolean"||
   !TEST_HOURS.includes(durationHours)||
   !Number.isSafeInteger(expectedRevision)||expectedRevision<0)
  throw Error("V2_DEVICE_POLICY_INVALID");
 const root=options.root||ROOT,now=options.now??Date.now();
 if(!Number.isSafeInteger(now)||now<=0)throw Error("V2_DEVICE_POLICY_INVALID");
 return withFileLock(root,"v2-device-policy",async()=>{
  const previous=(await read(root))||defaults();
  if(previous.revision!==expectedRevision)throw Error("V2_DEVICE_POLICY_CONFLICT");
  const isRelaxed=patchMonths!==12||!enforcePatch||!enforceBoot;
  const next=validate({version:1,patchMonths,enforcePatch,enforceBoot,
   expiresAt:isRelaxed?now+durationHours*3600000:0,
   revision:previous.revision+1});
  await atomicJson(root,FILE,next);
  return v2DevicePolicyStatus({root,now});
 });
}
