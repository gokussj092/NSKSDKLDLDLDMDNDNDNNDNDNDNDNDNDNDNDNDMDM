import {randomUUID} from 'node:crypto';
import {adminSettings,authenticateAdmin,validMutation} from './c6-admin-auth.mjs';
import {opsStore} from './c6-ops-store.mjs';
import {legacyProtectionStatus,setLegacyProtection} from './v1-compat-policy.mjs';

const reply=(data,status=200)=>Response.json(data,{status,headers:{'Cache-Control':'private, no-store'}});
export async function adminV1Protection(request,{storeProvider=opsStore,read=legacyProtectionStatus,write=setLegacyProtection}={}){
  const cfg=adminSettings();
  if(!cfg.enabled)return reply({code:'ADMIN_DISABLED'},503);
  if(request.method==='POST'&&!validMutation(request,cfg))return reply({code:'CSRF_REJECTED'},403);
  if(request.method!=='GET'&&request.method!=='POST')return reply({code:'METHOD_NOT_ALLOWED'},405);
  try{
    const redis=await storeProvider();
    if(!await authenticateAdmin(redis,request,cfg))return reply({code:'UNAUTHORIZED'},401);
    if(request.method==='GET')return reply({policy:await read()});
    if(request.headers.get('content-length') && Number(request.headers.get('content-length'))>256)
      return reply({code:'INVALID_REQUEST'},400);
    const reader=request.body?.getReader();if(!reader)return reply({code:'INVALID_REQUEST'},400);
    let size=0;const chunks=[];
    try{
      for(;;){const {value,done}=await reader.read();if(done)break;
        size+=value.length;if(size>256){await reader.cancel();return reply({code:'INVALID_REQUEST'},400);}
        chunks.push(Buffer.from(value));}
    }finally{reader.releaseLock();}
    let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return reply({code:'INVALID_REQUEST'},400);}
    if(!body || Object.keys(body).sort().join(',')!=='confirmation,strict' ||
       typeof body.strict!=='boolean' ||
       body.confirmation!==(body.strict?'ACTIVAR_V1_ESTRICTO':'DESACTIVAR_V1_ESTRICTO'))
      return reply({code:'INVALID_REQUEST'},400);
    const lock='spc6:v1-security:admin-lock',token=randomUUID();
    if(await redis.set(lock,token,{NX:true,EX:30})!=='OK')return reply({code:'BUSY'},409);
    try{return reply({policy:await write(body.strict)});}
    finally{await redis.eval("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",{keys:[lock],arguments:[token]}).catch(()=>{});}
  }catch(error){
    if(error?.message==='V2_NOT_CONFIGURED')return reply({code:'V2_NOT_CONFIGURED'},409);
    if(error?.message==='V1_POLICY_LOCKED')return reply({code:'V1_POLICY_LOCKED'},409);
    return reply({code:'SERVICE_UNAVAILABLE'},503);
  }
}
