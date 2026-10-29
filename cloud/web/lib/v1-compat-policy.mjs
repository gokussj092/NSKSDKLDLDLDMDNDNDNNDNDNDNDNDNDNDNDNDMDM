import {randomUUID} from 'node:crypto';
import {open,readFile,rename,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {v2Settings} from './v2-config.mjs';

// Only an allowlisted Boolean is persisted. Never accept arbitrary policy flags.
const ROOT='/app/provider-control';
const FILE='v1-security.json';
export async function legacyProtectionStatus(env=process.env,{root=ROOT}={}){
  const locked=env.CLOUD_V1_REQUIRE_BOUND_SESSION==='true';
  if(locked)return {strict:true,locked:true};
  let raw;
  try{raw=await readFile(join(root,FILE),'utf8');}
  catch(error){if(error?.code==='ENOENT')return {strict:false,locked:false};throw error;}
  if(raw.length>256)throw Error('V1_POLICY_INVALID');
  const parsed=JSON.parse(raw);
  if(!parsed || typeof parsed!=='object' || Array.isArray(parsed) ||
    Object.keys(parsed).sort().join(',')!=='strict,updatedAt' ||
    typeof parsed.strict!=='boolean' ||
    typeof parsed.updatedAt!=='string' ||
    !/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$/.test(parsed.updatedAt))
    throw Error('V1_POLICY_INVALID');
  return {strict:parsed.strict,locked:false};
}
export async function setLegacyProtection(strict,env=process.env,{root=ROOT,v2Ready=v2Settings(env).configured}={}){
  if(typeof strict!=='boolean')throw Error('V1_POLICY_INVALID');
  if(env.CLOUD_V1_REQUIRE_BOUND_SESSION==='true')throw Error('V1_POLICY_LOCKED');
  if(strict&&!v2Ready)throw Error('V2_NOT_CONFIGURED');
  const tmp=join(root,'.v1-security-'+randomUUID());
  const doc=JSON.stringify({strict,updatedAt:new Date().toISOString()})+'\n';
  const file=await open(tmp,'wx',0o600);
  try{await file.writeFile(doc,'utf8');await file.sync();}
  finally{await file.close();}
  try{await rename(tmp,join(root,FILE));}
  catch(error){await unlink(tmp).catch(()=>{});throw error;}
  return legacyProtectionStatus(env,{root});
}
