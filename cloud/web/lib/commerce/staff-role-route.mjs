import {requirePanel} from './staff.mjs';
import {customRoles,writeCustomRole} from './staff-roles.mjs';
import {safe,reply,jsonBody,fail} from './config.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';

export const panelRoleRequest=request=>safe(async()=>{
 const principal=await requirePanel(request,request.method==='GET'?'staff.read':'staff.write');
 if(request.method==='GET')return reply(await customRoles());
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 if(principal.role!=='owner')fail('FORBIDDEN',403);
 if(!validMutation(request,adminSettings()))fail('CSRF_REJECTED',403);
 return reply(await writeCustomRole(principal,await jsonBody(request,1400)));
});
