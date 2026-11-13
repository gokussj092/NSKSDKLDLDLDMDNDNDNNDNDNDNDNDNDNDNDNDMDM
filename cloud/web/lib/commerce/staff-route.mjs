import {requirePanel,createStaff,updateStaff,listStaff,changeStaffPassword,
 recentStaffAudit,STAFF_ROLES} from './staff.mjs';
import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';
const changeAllowed=request=>{
 if(!validMutation(request,adminSettings()))fail('CSRF_REJECTED',403);
};
export const panelAccessRequest=request=>safe(async()=>{
 const principal=await requirePanel(request,null);
 return reply({principal:{id:principal.id,username:principal.username,name:principal.name,
  role:principal.role,mustChangePassword:principal.mustChangePassword,
  capabilities:principal.mustChangePassword?[]:principal.capabilities}});
});
export const panelStaffRequest=request=>safe(async()=>{
 if(request.method==='GET'){
  await requirePanel(request,'staff.read');
  return reply(await listStaff());
 }
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 changeAllowed(request);
 const principal=await requirePanel(request,'staff.write');
 if(principal.role!=='owner')fail('FORBIDDEN',403);
 const body=await jsonBody(request,2048);
 if(!body||Array.isArray(body)||typeof body!=='object')fail('INVALID_REQUEST');
 const {action,...options}=body;
 if(action==='create')return reply(await createStaff(principal,options),201);
 if(action==='update')return reply(await updateStaff(principal,options));
 fail('INVALID_REQUEST');
});
export const panelStaffPasswordRequest=request=>safe(async()=>{
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 changeAllowed(request);
 const principal=await requirePanel(request,null);
 if(principal.role==='owner')fail('FORBIDDEN',403);
 const input=await jsonBody(request,1200);
 if(!input||typeof input!=='object'||Array.isArray(input)||
    Object.keys(input).some(k=>!['currentPassword','newPassword'].includes(k)))
  fail('INVALID_REQUEST');
 return reply(await changeStaffPassword(principal,input.currentPassword,input.newPassword));
});
export const panelStaffAuditRequest=request=>safe(async()=>{
 await requirePanel(request,'audit.read');
 return reply(await recentStaffAudit());
});
