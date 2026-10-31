/** Durable, independent V1 controls. Neither deprecated environment flag changes defaults. */
import {readFile,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {withFileLock,atomicJson} from './durable-json.mjs';
const ROOT=process.env.CLOUD_V1_POLICY_ROOT||'/app/provider-control',FILE='v1-protection.json';
const DAY=86400000,RETIREMENT_DELAY=2*DAY;
const initial=()=>({version:2,enabled:false,apiEnabled:true,revision:0});
const effective=(p,now=Date.now())=>p.apiEnabled&&!(p.retireAt&&now>=p.retireAt);
function validate(v) {
 if(!v||typeof v!=='object'||Array.isArray(v))throw Error('V1_POLICY_INVALID');
 if(v.version===1&&Object.keys(v).sort().join(',')==='enabled,version'&&typeof v.enabled==='boolean')
   return {...initial(),enabled:v.enabled};
 const standard=Object.keys(v).sort().join(',')==='apiEnabled,enabled,revision,version'&&v.version===2;
 const scheduled=Object.keys(v).sort().join(',')==='apiEnabled,enabled,retireAt,revision,version'&&v.version===3;
 if((!standard&&!scheduled)||
   typeof v.enabled!=='boolean'||typeof v.apiEnabled!=='boolean'||
   !Number.isSafeInteger(v.revision)||v.revision<0||
   (scheduled&&(!Number.isSafeInteger(v.retireAt)||v.retireAt<=0||v.retireAt>8640000000000000)))
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
 return {advancedProtection:p.enabled,apiEnabled:effective(p),revision:p.revision,
   ...(p.retireAt?{retireAt:p.retireAt,retired:Date.now()>=p.retireAt}: {})};
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
  return {advancedProtection:next.enabled,apiEnabled:effective(next),revision:next.revision,
    ...(next.retireAt?{retireAt:next.retireAt,retired:Date.now()>=next.retireAt}: {})};
 });
}
export async function setV1Protection(enabled,options={}) {
 const status=await v1PolicyStatus(options);await changeV1Policy('advancedProtection',enabled,status.revision,options);
 return v1ProtectionStatus(process.env,options);
}

/** Explicitly scheduled owner action: 48 hours from server time.
 * The durable cutoff is enforced on each V1 request, no cron/Actions needed.
 * Canceling a retirement never implicitly enables an API manually disabled.
 */
export async function changeV1Retirement(action,expectedRevision,options={}){
 if(!['schedule','cancel'].includes(action)||!Number.isSafeInteger(expectedRevision)||
    expectedRevision<0)throw Error('V1_POLICY_INVALID');
 const root=options.root||ROOT,now=options.now??Date.now();
 if(!Number.isSafeInteger(now)||now<=0)throw Error('V1_POLICY_INVALID');
 return withFileLock(root,'v1-policy',async()=>{
  const previous=(await read(root))||initial();
  if(previous.revision!==expectedRevision)throw Error('V1_POLICY_CONFLICT');
  if(action==='schedule'&&(!previous.apiEnabled||previous.retireAt))
    throw Error('V1_POLICY_CONFLICT');
  if(action==='cancel'&&!previous.retireAt)
    throw Error('V1_POLICY_CONFLICT');
  const next=action==='schedule'
   ?{...previous,version:3,retireAt:now+RETIREMENT_DELAY,revision:previous.revision+1}
   :{version:2,enabled:previous.enabled,apiEnabled:previous.apiEnabled,revision:previous.revision+1};
  await atomicJson(root,FILE,next);
  return {advancedProtection:next.enabled,apiEnabled:effective(next,now),
   revision:next.revision,...(next.retireAt?{retireAt:next.retireAt,retired:false}:{})};
 });
}
