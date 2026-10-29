/** Operator-only V1 protection toggle. Legacy behavior is preserved by default.
 * The VPS environment can enforce strict mode and cannot be overridden by UI.
 * Only a Boolean is stored; no tokens, sessions or client material.
 */
import {readFile,open,rename,unlink} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
const ROOT='/app/provider-control';
const FILE='v1-security.json';
export async function readV1Protection({root=ROOT,env=process.env}={}) {
  const locked=env.CLOUD_V1_REQUIRE_BOUND_SESSION==='true';
  let state=false;
  try{
    const raw=await readFile(join(root,FILE),'utf8');
    if(raw.length>128)throw Error('V1_POLICY_INVALID');
    const parsed=JSON.parse(raw);
    if(!parsed||Object.keys(parsed).length!==1||typeof parsed.strict!=='boolean')throw Error('V1_POLICY_INVALID');
    state=parsed.strict;
  }catch(e){if(e?.code!=='ENOENT')throw Error('V1_POLICY_INVALID');}
  return {enabled:locked||state,locked};
}
export async function setV1Protection(strict,{root=ROOT,env=process.env}={}) {
  if(typeof strict!=='boolean')throw Error('INVALID_REQUEST');
  if(env.CLOUD_V1_REQUIRE_BOUND_SESSION==='true'&&!strict)throw Error('V1_POLICY_LOCKED');
  if(env.CLOUD_LEGACY_API_ENABLED==='false')throw Error('V1_RETIRED');
  const lock=join(root,'v1-security.lock');
  let handle;
  for(let n=0;n<15;n++){
    try{handle=await open(lock,'wx',0o600);break;}
    catch(e){if(e?.code!=='EEXIST')throw e;await new Promise(resolve=>setTimeout(resolve,75));}
  }
  if(!handle)throw Error('V1_POLICY_BUSY');
  try{
    const target=join(root,FILE),temporary=join(root,'.v1-security-'+randomUUID());
    const out=await open(temporary,'wx',0o600);
    try{await out.writeFile(JSON.stringify({strict})+'\n');await out.sync();}
    finally{await out.close();}
    try{await rename(temporary,target);}
    catch(e){await unlink(temporary).catch(()=>{});throw e;}
    return readV1Protection({root,env});
  }finally{await handle.close();await unlink(lock).catch(()=>{});}
}
