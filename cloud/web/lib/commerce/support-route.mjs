import {requireAccount} from './auth.mjs';
import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {createSupportThread,sendSupportMessage,listUserSupport,listAdminSupport,
  replyAdminSupport,assignSupportThread,escalateSupportThread,markSupportThreadRead,
  liftSupportSuspension} from './support.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';
import {requirePanel,can} from './staff.mjs';
import {touchStaffPresence} from './staff-presence.mjs';

export const supportUserRequest=request=>safe(async()=>{
 const session=await requireAccount(request);
 if(request.method==='GET')return reply(await listUserSupport(session.user.id,{
  sharedAvatars:request.headers.get('x-spdecode-support-avatars')==='shared-v1'}));
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
 // Presencia real: cualquier actividad del personal en soporte (listar, leer,
 // responder, asignar, escalar) refresca su clave 20 min. El owner no es
 // personal (no tiene sessionId) y no marca presencia. Best-effort: un fallo
 // de Redis jamás bloquea la petición.
 if(principal.sessionId)await touchStaffPresence(null,principal.id);
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
 if(body.action==='liftSuspension'){
   if(!can(principal,'support.write'))fail('FORBIDDEN',403);
   if(Object.keys(body).some(k=>!['action','accountId'].includes(k)))fail('INVALID_REQUEST');
   return reply(await liftSupportSuspension(principal,body.accountId));
 }
 if(body.action==='escalate'){
   // Permission lives inside escalateSupportThread: support.assign on any
   // thread, or the assigned agent with support.write on their own thread.
   if(Object.keys(body).some(k=>!['action','threadId'].includes(k)))fail('INVALID_REQUEST');
   return reply(await escalateSupportThread(principal,body));
 }
 if(!can(principal,'support.write'))fail('FORBIDDEN',403);
 return reply(await replyAdminSupport({
   id:principal.id,name:principal.name,role:principal.role,
   avatar:principal.avatar??null,
   canAssign:principal.capabilities.includes('support.assign')
 },body));
});
