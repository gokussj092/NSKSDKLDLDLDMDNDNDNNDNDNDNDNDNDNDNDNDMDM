/** Durable V2 availability; independent of V1 and without relaxation of V2 protections. */
import {readFile,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {withFileLock,atomicJson} from './durable-json.mjs';
const ROOT=process.env.CLOUD_V2_POLICY_ROOT||'/app/provider-control';
const FILE='v2-availability.json';
const initial=()=>({version:1,enabled:true,revision:0});
function validate(v) {
 if(!v||typeof v!=='object'||Array.isArray(v)||
    Object.keys(v).sort().join(',')!=='enabled,revision,version'||
    v.version!==1||typeof v.enabled!=='boolean'||
    !Number.isSafeInteger(v.revision)||v.revision<0)
  throw Error('V2_POLICY_INVALID');
 return v;
}
async function read(root) {
 let raw;
 try{raw=await readFile(join(root,FILE),'utf8');}
 catch(e){if(e.code==='ENOENT')return null;throw Error('V2_POLICY_UNAVAILABLE');}
 if(Buffer.byteLength(raw)>1024)throw Error('V2_POLICY_INVALID');
 try{return validate(JSON.parse(raw));}catch{throw Error('V2_POLICY_INVALID');}
}
export async function loadV2Availability(options={}) {
 const root=options.root||ROOT;
 try{if(!(await stat(root)).isDirectory())throw Error('NOT_DIRECTORY');}
 catch(e){
  if(e.code==='ENOENT'&&!options.root&&process.env.NODE_ENV!=='production')return initial();
  throw Error('V2_POLICY_UNAVAILABLE');
 }
 const saved=await read(root);if(saved)return saved;
 return withFileLock(root,'v2-policy',async()=>{
  const existing=await read(root);if(existing)return existing;
  const next=initial();await atomicJson(root,FILE,next);return next;
 });
}
export async function v2PolicyStatus(options={}) {
 const p=await loadV2Availability(options);
 return {enabled:p.enabled,revision:p.revision};
}
export async function changeV2Availability(enabled,expectedRevision,options={}) {
 if(typeof enabled!=='boolean'||!Number.isSafeInteger(expectedRevision)||expectedRevision<0)
  throw Error('V2_POLICY_INVALID');
 const root=options.root||ROOT;
 return withFileLock(root,'v2-policy',async()=>{
  const p=(await read(root))||initial();
  if(p.revision!==expectedRevision)throw Error('V2_POLICY_CONFLICT');
  const next={...p,enabled,revision:p.revision+1};
  await atomicJson(root,FILE,next);
  return {enabled:next.enabled,revision:next.revision};
 });
}
