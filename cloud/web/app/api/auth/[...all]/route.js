import {accountAuth} from '../../../../lib/commerce/auth.mjs';
import {safe,requireOrigin,jsonBody,fail} from '../../../../lib/commerce/config.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
async function handle(request){return safe(async()=>{
  const path=new URL(request.url).pathname;
  const allowed=new Set(['/api/auth/sign-in/social','/api/auth/callback/google','/api/auth/get-session',
    '/api/auth/sign-out','/api/auth/delete-user','/api/auth/error','/api/auth/ok']);
  if(!allowed.has(path))fail('NOT_FOUND',404);
  if(request.method==='POST'){
    requireOrigin(request);
    if(path.endsWith('/sign-in/social')){
      const body=await jsonBody(request.clone(),4096);
      if(body.provider!=='google'||body.idToken||body.requestSignUp!==undefined)fail('INVALID_REQUEST');
      if(body.acceptedTerms!=='2026-11-10'||body.acceptedPrivacy!=='2026-11-10')fail('CONSENT_REQUIRED');
    }
  }
  const response=await accountAuth().handler(request);
  response.headers.set('Cache-Control','private, no-store, max-age=0');return response;
});}
export const GET=handle;
export const POST=handle;
