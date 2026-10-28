import {adminSettings,authenticateAdmin,validMutation} from './c6-admin-auth.mjs';
import {opsStore} from './c6-ops-store.mjs';
import {exportPolicy,setExportPolicy} from './compatible-export-policy.mjs';
import {boundedBody} from './c3-gateway.mjs';
const reply=(value,status=200)=>Response.json(value,{status,headers:{'Cache-Control':'private, no-store'}});
export async function compatibleExportAdmin(request,{storeProvider=opsStore,policyOptions={}}={}){
 const cfg=adminSettings();
 if(!cfg.enabled)return reply({error:{code:'ADMIN_DISABLED'}},503);
 if(request.method==='POST'&&!validMutation(request,cfg))return reply({error:{code:'CSRF_REJECTED'}},403);
 try{
  const redis=await storeProvider();
  if(!await authenticateAdmin(redis,request,cfg))return reply({error:{code:'UNAUTHORIZED'}},401);
  if(request.method==='GET')return reply({status:'ok',compatibleExports:await exportPolicy(policyOptions)});
  if(request.method!=='POST')return reply({error:{code:'METHOD_NOT_ALLOWED'}},405);
  const body=await boundedBody(request,512);
  return reply({status:'ok',compatibleExports:await setExportPolicy(body,policyOptions)});
 }catch(error){
  const code=['INVALID_REQUEST','EXPORT_POLICY_LOCKED','EXPORT_POLICY_CONFLICT'].includes(error?.code)?error.code:'SERVICE_UNAVAILABLE';
  return reply({error:{code}},code==='INVALID_REQUEST'?400:code==='SERVICE_UNAVAILABLE'?503:409);
 }
}
