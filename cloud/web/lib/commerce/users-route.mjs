import {userDirectory,userDetail} from './users-admin.mjs';
import {requirePanel} from './staff.mjs';
import {safe,reply,fail} from './config.mjs';
export const adminUsersRequest=request=>safe(async()=>{
 const principal=await requirePanel(request,'users.read');
 if(request.method!=='GET')fail('METHOD_NOT_ALLOWED',405);
 const url=new URL(request.url),params=url.searchParams;
 if([...params.keys()].some(x=>!['q','page','id'].includes(x)))fail('INVALID_REQUEST');
 if(params.has('id')){
   if(params.has('q')||params.has('page'))fail('INVALID_REQUEST');
   return reply(await userDetail(principal,params.get('id')));
 }
 const page=params.get('page')??'0';
 if(!/^(0|[1-9]\d{0,3})$/.test(page))fail('INVALID_REQUEST');
 return reply(await userDirectory({search:params.get('q')||'',page:Number(page)}));
});
