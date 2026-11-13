import {requireAccount} from './auth.mjs';
import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {createSupportThread,sendSupportMessage,listUserSupport,listAdminSupport,
  replyAdminSupport} from './support.mjs';
import {adminSettings,authenticateAdmin,validMutation} from '../c6-admin-auth.mjs';
import {opsStore} from '../c6-ops-store.mjs';

export const supportUserRequest=request=>safe(async()=>{
 const session=await requireAccount(request);
 if(request.method==='GET')return reply(await listUserSupport(session.user.id));
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const input=await jsonBody(request,6200);
 if(!input||typeof input!=='object'||Array.isArray(input))fail('INVALID_REQUEST');
 if(input.action==='new'&&Object.keys(input).every(x=>['action','subject','category','message'].includes(x)))
   return reply(await createSupportThread(session.user.id,{subject:input.subject,category:input.category,message:input.message}),201);
 if(input.action==='send'&&Object.keys(input).every(x=>['action','threadId','message'].includes(x)))
   return reply(await sendSupportMessage(session.user.id,input.threadId,{message:input.message}));
 fail('INVALID_REQUEST');
});
export const supportAdminRequest=request=>safe(async()=>{
 const settings=adminSettings(),redis=await opsStore();
 const actor=await authenticateAdmin(redis,request,settings);
 if(!actor)fail('UNAUTHORIZED',401);
 if(request.method==='GET')return reply(await listAdminSupport());
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 if(!validMutation(request,settings))fail('CSRF_REJECTED',403);
 const body=await jsonBody(request,6200);
 // Identity is derived from the verified administrator session, never the request.
 const claimedName=(process.env.SPDECODE_SUPPORT_AGENT_NAME||settings.username||'').trim();
 const displayName=claimedName.length>=2&&claimedName.length<=80?claimedName:settings.username;
 return reply(await replyAdminSupport({
   id:actor.sub,name:displayName,role:'owner'
 },body));
});
