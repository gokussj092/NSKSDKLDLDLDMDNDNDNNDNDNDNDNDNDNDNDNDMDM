import {requireAccount} from './auth.mjs';
import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {createSupportThread,sendSupportMessage,listUserSupport,listAdminSupport,
  replyAdminSupport,assignSupportThread,markSupportThreadRead} from './support.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';
import {requirePanel,can} from './staff.mjs';

export const supportUserRequest=request=>safe(async()=>{
 const session=await requireAccount(request);
 if(request.method==='GET')return reply(await listUserSupport(session.user.id));
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const input=await jsonBody(request,6200);
 if(!input||typeof input!=='object'||Array.isArray(input))fail('INVALID_REQUEST');
 if(input.action==='read'&&Object.keys(input).every(x=>['action','threadId'].includes(x)))
   return reply(await markSupportThreadRead(input.threadId,
     {kind:'user',id:session.user.id}));
 if(input.action==='new'&&Object.keys(input).every(x=>['action','subject','category','message'].includes(x)))
   return reply(await createSupportThread(session.user.id,{subject:input.subject,category:input.category,message:input.message}),201);
 if(input.action==='send'&&Object.keys(input).every(x=>['action','threadId','message'].includes(x)))
   return reply(await sendSupportMessage(session.user.id,input.threadId,{message:input.message}));
 fail('INVALID_REQUEST');
});
export const supportAdminRequest=request=>safe(async()=>{
 // Permiso por acción (antes todo POST exigía support.write): leer y marcar leído
 // bastan con support.read; responder sigue exigiendo support.write.
 const principal=await requirePanel(request);
 if(request.method==='GET'){
   if(!can(principal,'support.read'))fail('FORBIDDEN',403);
   return reply(await listAdminSupport({principal}));
 }
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 if(!validMutation(request,adminSettings()))fail('CSRF_REJECTED',403);
 const body=await jsonBody(request,6200);
 if(!body||typeof body!=='object'||Array.isArray(body))fail('INVALID_REQUEST');
 if(body.action==='assign'){
   if(!principal.capabilities.includes('support.assign'))fail('FORBIDDEN',403);
   return reply(await assignSupportThread(principal,body));
 }
 if(body.action==='read'){
   if(!can(principal,'support.read'))fail('FORBIDDEN',403);
   return reply(await markSupportThreadRead(body.threadId,{
     kind:'staff',id:principal.id,
     canSeeAll:principal.capabilities.includes('support.assign')}));
 }
 if(!can(principal,'support.write'))fail('FORBIDDEN',403);
 return reply(await replyAdminSupport({
   id:principal.id,name:principal.name,role:principal.role,
   avatar:principal.avatar??null,
   canAssign:principal.capabilities.includes('support.assign')
 },body));
});
