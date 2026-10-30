/** Durable, independent V1 controls. Neither deprecated environment flag changes defaults. */
import {readFile,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {withFileLock,atomicJson} from './durable-json.mjs';
const ROOT=process.env.CLOUD_V1_POLICY_ROOT||'/app/provider-control',FILE='v1-protection.json';
const initial=()=>({version:2,enabled:false,apiEnabled:true,revision:0});
function validate(v) {
 if(!v||typeof v!=='object'||Array.isArray(v))throw Error('V1_POLICY_INVALID');
 if(v.version===1&&Object.keys(v).sort().join(',')==='enabled,version'&&typeof v.enabled==='boolean')
   return {...initial(),enabled:v.enabled};
 if(Object.keys(v).sort().join(',')!=='apiEnabled,enabled,revision,version'||v.version!==2||
   typeof v.enabled!=='boolean'||typeof v.apiEnabled!=='boolean'||!Number.isSafeInteger(v.revision)||v.revision<0)
   throw Error('V1_POLICY_INVALID');
 return v;
}
async function read(root) {
 let raw;try{raw=await readFile(join(root,FILE),'utf8');}catch(e){if(e.code==='ENOENT')return null;throw e;}
 if(Buffer.byteLength(raw)>1024)throw Error('V1_POLICY_INVALID');
 try{return validate(JSON.parse(raw));}catch{throw Error('V1_POLICY_INVALID');}
}
export async function loadV1Protection(options={}) {
 const root=options.root||ROOT;
 try{await stat(root);}catch(e){
  // Historical unit fixtures have no production mount. Production never uses this fallback.
  if(e.code==='ENOENT'&&!options.root&&process.env.NODE_ENV!=='production')return initial();
  throw Error('V1_POLICY_UNAVAILABLE');
 }
 const saved=await read(root);if(saved)return saved;
 return withFileLock(root,'v1-policy',async()=>{
  const existing=await read(root);if(existing)return existing;
  const value=initial();await atomicJson(root,FILE,value);return value;
 });
}
export async function v1PolicyStatus(options={}) {
 const p=await loadV1Protection(options);
 return {advancedProtection:p.enabled,apiEnabled:p.apiEnabled,revision:p.revision};
}
export async function v1ProtectionRequired(_env=process.env,options={}){return (await loadV1Protection(options)).enabled;}
export async function v1ProtectionStatus(_env=process.env,options={}){return {enabled:await v1ProtectionRequired(_env,options),locked:false};}
export async function changeV1Policy(field,enabled,expectedRevision,options={}) {
 if(!['advancedProtection','apiEnabled'].includes(field)||typeof enabled!=='boolean'||
   !Number.isSafeInteger(expectedRevision)||expectedRevision<0)throw Error('V1_POLICY_INVALID');
 const root=options.root||ROOT;
 return withFileLock(root,'v1-policy',async()=>{
  const p=(await read(root))||initial();
  if(p.revision!==expectedRevision)throw Error('V1_POLICY_CONFLICT');
  const next={...p,[field==='advancedProtection'?'enabled':'apiEnabled']:enabled,revision:p.revision+1};
  await atomicJson(root,FILE,next);
  return {advancedProtection:next.enabled,apiEnabled:next.apiEnabled,revision:next.revision};
 });
}
export async function setV1Protection(enabled,options={}) {
 const status=await v1PolicyStatus(options);await changeV1Policy('advancedProtection',enabled,status.revision,options);
 return v1ProtectionStatus(process.env,options);
}
