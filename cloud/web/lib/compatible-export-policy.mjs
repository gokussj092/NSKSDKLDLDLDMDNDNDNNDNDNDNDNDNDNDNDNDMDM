/** Additive protocol negotiation, not client authentication or file authorization. */
import {readFile,mkdir,open,rename,unlink,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {publicFormats} from './file-format-catalog.mjs';

export const EXPORT_HEADER='x-spdecode-compatible-export';
export const HAT_EXPORT_HEADER='x-spdecode-compatible-export-hat';
export const EXPORT_PROFILE='original-app-open-v1';
export const EXPORT_PROTOCOL_FLOOR='1.1.21';
const ROOT='/app/provider-control';
const DEFAULT=Object.freeze({schemaVersion:1,revision:0,enabled:false,minimumAppVersion:EXPORT_PROTOCOL_FLOOR});
// One curated, static export registry shared with the isolated Python worker.
// A decoder becoming available does NOT make its output safely exportable.
const LEGACY_SUFFIXES=Object.freeze(['hc','dark','ehi','npvs','hat']);
export function validateExportRegistry(registry,{knownFormats=publicFormats()}={}) {
 const same=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&
   Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
 if(!same(registry,['schemaVersion','revision','formats'])||
    registry.schemaVersion!==1||!Number.isSafeInteger(registry.revision)||
    registry.revision<1||registry.revision>100000 ||
    !Array.isArray(registry.formats)||registry.formats.length<LEGACY_SUFFIXES.length||
    registry.formats.length>64)throw Error('EXPORT_REGISTRY_INVALID');
 const allowed=new Set(knownFormats.map(f=>f.suffix));
 const observed=new Set(),identities=new Set();
 for(const f of registry.formats) {
  if(!same(f,['suffix','targetAppId','name','banner']) ||
     typeof f.suffix!=='string'||!/^[a-z0-9][a-z0-9_-]{0,15}$/.test(f.suffix)||
     !allowed.has(f.suffix)||!observed.add(f.suffix) ||
     typeof f.targetAppId!=='string'||!/^[a-z0-9][a-z0-9-]{0,47}$/.test(f.targetAppId)||
     !identities.add(f.targetAppId) ||
     typeof f.name!=='string'||f.name!==f.name.trim()||f.name.length<1||
     f.name.length>80||/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(f.name)||
     !['none','spdecode-html'].includes(f.banner)) throw Error('EXPORT_REGISTRY_INVALID');
 }
 if(LEGACY_SUFFIXES.some(s=>!observed.has(s)))throw Error('EXPORT_REGISTRY_INVALID');
 return Object.freeze({schemaVersion:1,revision:registry.revision,
  formats:Object.freeze(registry.formats.map(f=>Object.freeze({...f})))});
}
let registryCache=null;
export function exportRegistry() {
 if(registryCache)return registryCache;
 const bytes=readFileSync(new URL('../content/compatible-export-formats.json',import.meta.url),'utf8');
 if(Buffer.byteLength(bytes)>32768)throw Error('EXPORT_REGISTRY_INVALID');
 registryCache=validateExportRegistry(JSON.parse(bytes));
 return registryCache;
}
export function negotiatesDynamicExport(request) {
 return negotiatesExport(request)&&
   request.headers.get(EXPORT_HEADER)==='2'&&
   atLeast(request.headers.get('x-spdecode-app-version'),'1.1.26');
}

export function version(value){
 if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$/.test(value))return null;
 return value.split('.').map(Number);
}
export function atLeast(value,floor){
 const a=version(value),b=version(floor);if(!a||!b)return false;
 for(let i=0;i<3;i++){if(a[i]!==b[i])return a[i]>b[i];}return true;
}
export function negotiatesExport(request){
 return ['1','2'].includes(request.headers.get(EXPORT_HEADER))&&
  atLeast(request.headers.get('x-spdecode-app-version'),EXPORT_PROTOCOL_FLOOR);
}
// Old Android clients accept at most four fixed targets. Advertise HA only
// to clients that explicitly understand the additive fifth target.
export function negotiatesHatExport(request){
 return negotiatesExport(request)&&request.headers.get(HAT_EXPORT_HEADER)==='1';
}
function valid(p){
 return p&&typeof p==='object'&&!Array.isArray(p)&&
  Object.keys(p).sort().join(',')==='enabled,minimumAppVersion,revision,schemaVersion'&&
  p.schemaVersion===1&&Number.isSafeInteger(p.revision)&&p.revision>=0&&p.revision<1_000_000&&
  typeof p.enabled==='boolean'&&atLeast(p.minimumAppVersion,EXPORT_PROTOCOL_FLOOR);
}
export async function exportPolicy({root=ROOT,env=process.env}={}){
 let p;
 try{
  const raw=await readFile(join(root,'compatible-export.json'),'utf8');
  if(Buffer.byteLength(raw)>1024)throw Error('EXPORT_POLICY_INVALID');
  p=JSON.parse(raw);if(!valid(p))throw Error('EXPORT_POLICY_INVALID');
 }catch(error){if(error?.code!=='ENOENT')throw error;p={...DEFAULT};}
 return {...p,locked:env.CLOUD_COMPATIBLE_EXPORT_LOCKED==='true',
  enabled:p.enabled&&env.CLOUD_COMPATIBLE_EXPORT_LOCKED!=='true'};
}
export async function setExportPolicy(input,{root=ROOT,env=process.env}={}){
 if(env.CLOUD_COMPATIBLE_EXPORT_LOCKED==='true')throw Object.assign(Error('locked'),{code:'EXPORT_POLICY_LOCKED'});
 if(!input||Object.keys(input).sort().join(',')!=='enabled,expectedRevision,minimumAppVersion'||
    typeof input.enabled!=='boolean'||!Number.isSafeInteger(input.expectedRevision)||
    !atLeast(input.minimumAppVersion,EXPORT_PROTOCOL_FLOOR))throw Object.assign(Error('schema'),{code:'INVALID_REQUEST'});
 await mkdir(root,{recursive:true,mode:0o700});
 const lock=join(root,'.compatible-export.lock');let handle;
 for(let i=0;i<30;i++){
  try{handle=await open(lock,'wx',0o600);break;}
  catch(error){
   if(error?.code!=='EEXIST')throw error;
   const info=await stat(lock).catch(()=>null);
   if(info&&Date.now()-info.mtimeMs>30_000)await unlink(lock).catch(()=>{});
   await new Promise(resolve=>setTimeout(resolve,20));
  }
 }
 if(!handle)throw Object.assign(Error('busy'),{code:'EXPORT_POLICY_CONFLICT'});
 try{
  const before=await exportPolicy({root,env});
  if(before.revision!==input.expectedRevision)throw Object.assign(Error('revision'),{code:'EXPORT_POLICY_CONFLICT'});
  const next={schemaVersion:1,revision:before.revision+1,enabled:input.enabled,minimumAppVersion:input.minimumAppVersion};
  if(!valid(next))throw Object.assign(Error('schema'),{code:'INVALID_REQUEST'});
  const tmp=join(root,'.compatible-export-'+randomUUID());
  const file=await open(tmp,'wx',0o600);
  try{await file.writeFile(JSON.stringify(next)+'\n');await file.sync();}finally{await file.close();}
  try{await rename(tmp,join(root,'compatible-export.json'));}
  catch(error){await unlink(tmp).catch(()=>{});throw error;}
  return {...next,locked:false};
 }finally{await handle.close();await unlink(lock).catch(()=>{});}
}
export function exportAllowed(request,policy){
 return negotiatesExport(request)&&policy.enabled&&
  atLeast(request.headers.get('x-spdecode-app-version'),policy.minimumAppVersion);
}
export function projectedCatalogVersion(request,base,policy){
 const result=negotiatesDynamicExport(request)
  ?base+policy.revision+exportRegistry().revision+4
  :negotiatesExport(request)?base+policy.revision+(negotiatesHatExport(request)?2:1):base;
 if(!Number.isSafeInteger(result)||result<1||result>=1_000_000_000)throw Error('CATALOG_VERSION_INVALID');
 return result;
}
export function exportCatalog(request,policy){
 if(!negotiatesExport(request))return null;
 const allowed=exportAllowed(request,policy);
 const registry=exportRegistry();
 const dynamic=negotiatesDynamicExport(request);
 const formats=allowed?(dynamic?registry.formats:
   registry.formats.filter(f=>LEGACY_SUFFIXES.includes(f.suffix)&&
     (f.suffix!=='hat'||negotiatesHatExport(request)))):[];
 return {schemaVersion:dynamic?2:1,revision:policy.revision,enabled:allowed,
  minimumAppVersion:policy.minimumAppVersion,profile:EXPORT_PROFILE,
  maxArtifactBytes:1024*1024,formats:formats.map(f=>({...f}))};
}
