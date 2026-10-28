/** Additive protocol negotiation, not client authentication or file authorization. */
import {readFile,mkdir,open,rename,unlink,stat} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';

export const EXPORT_HEADER='x-spdecode-compatible-export';
export const EXPORT_PROFILE='original-app-open-v1';
export const EXPORT_PROTOCOL_FLOOR='1.1.21';
const ROOT='/app/provider-control';
const DEFAULT=Object.freeze({schemaVersion:1,revision:0,enabled:false,minimumAppVersion:EXPORT_PROTOCOL_FLOOR});
const FORMATS=Object.freeze([
 {suffix:'hc',targetAppId:'http-custom',name:'HTTP Custom',banner:'spdecode-html'},
 {suffix:'dark',targetAppId:'dark-tunnel',name:'Dark Tunnel',banner:'none'},
 {suffix:'ehi',targetAppId:'http-injector',name:'HTTP Injector',banner:'spdecode-html'},
 {suffix:'npvs',targetAppId:'npv-tunnel',name:'NPV Tunnel',banner:'none'},
]);

export function version(value){
 if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$/.test(value))return null;
 return value.split('.').map(Number);
}
export function atLeast(value,floor){
 const a=version(value),b=version(floor);if(!a||!b)return false;
 for(let i=0;i<3;i++){if(a[i]!==b[i])return a[i]>b[i];}return true;
}
export function negotiatesExport(request){
 return request.headers.get(EXPORT_HEADER)==='1' &&
  atLeast(request.headers.get('x-spdecode-app-version'),EXPORT_PROTOCOL_FLOOR);
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
 const result=negotiatesExport(request)?base+policy.revision+1:base;
 if(!Number.isSafeInteger(result)||result<1||result>=1_000_000_000)throw Error('CATALOG_VERSION_INVALID');
 return result;
}
export function exportCatalog(request,policy){
 if(!negotiatesExport(request))return null;
 const allowed=exportAllowed(request,policy);
 return {schemaVersion:1,revision:policy.revision,enabled:allowed,
  minimumAppVersion:policy.minimumAppVersion,profile:EXPORT_PROFILE,
  maxArtifactBytes:1024*1024,formats:allowed?FORMATS.map(x=>({...x})):[]};
}
