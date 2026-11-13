import {requireAccount,accountAuth} from './auth.mjs';
import {safe,reply,requireOrigin,jsonBody,fail} from './config.mjs';
import {registerDevice,makeDeletionChallenge,authorizeDeviceDeletion,deleteAccountData} from './account-device.mjs';

export const registerDeviceRequest=request=>safe(async()=>{
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const session=await requireAccount(request,{fresh:true});
 return reply(await registerDevice(session.user.id,await jsonBody(request,4096)));
});
export const deleteChallengeRequest=request=>safe(async()=>{
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const session=await requireAccount(request);
 const input=await jsonBody(request,256);
 if(!input||Object.keys(input).some(x=>x!=='keyId'))fail('INVALID_REQUEST');
 return reply(await makeDeletionChallenge(session.user.id,input.keyId));
});
export const deleteAccountRequest=request=>safe(async()=>{
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const session=await requireAccount(request);
 const input=await jsonBody(request,4096);
 if(!input||typeof input!=='object'||Array.isArray(input)||
     !['password','device','google'].includes(input.method))fail('INVALID_REQUEST');
 if(input.method==='password'){
   if(Object.keys(input).some(k=>!['method','password'].includes(k))||
      typeof input.password!=='string'||input.password.length>128||!input.password)
     fail('INVALID_REQUEST');
   // Reauthenticate using Better Auth's configured and salted password verifier.
   // Do not examine or compare stored hashes in application code.
   let confirmed;
   try{
     confirmed=await accountAuth().api.signInEmail({
       body:{email:session.user.email,password:input.password,rememberMe:false},
       headers:request.headers});
   }catch{fail('INVALID_PASSWORD',403);}
   if(confirmed?.user?.id!==session.user.id)fail('INVALID_PASSWORD',403);
 }else if(input.method==='google'){
   if(Object.keys(input).some(k=>k!=='method'))fail('INVALID_REQUEST');
   await requireAccount(request,{fresh:true});
   const linked=await (await import('./db.mjs')).database().query(
     'SELECT 1 FROM shop_identity WHERE "userId"=$1 AND "providerId"=$2 LIMIT 1',
     [session.user.id,'google']);
   if(!linked.rowCount)fail('GOOGLE_ACCOUNT_REQUIRED',403);
 }else{
   if(Object.keys(input).some(k=>!['method','keyId','challengeId','challenge','signature'].includes(k)))
     fail('INVALID_REQUEST');
   await authorizeDeviceDeletion(session.user.id,input);
 }
 return reply(await deleteAccountData(session.user.id));
});
