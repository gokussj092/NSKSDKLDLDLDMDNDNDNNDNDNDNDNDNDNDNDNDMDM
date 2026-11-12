import {accountAuth} from '../../../../lib/commerce/auth.mjs';
import {safe,requireOrigin,jsonBody,fail,reply,authReady} from '../../../../lib/commerce/config.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
async function handle(request){return safe(async()=>{
  const path=new URL(request.url).pathname;
  if(path==='/api/auth/native-config'&&request.method==='GET')
    return reply({enabled:authReady(),googleWebClientId:authReady()?process.env.GOOGLE_CLIENT_ID:null});
  const allowed=new Set(['/api/auth/native-config','/api/auth/sign-in/social','/api/auth/callback/google','/api/auth/get-session',
    '/api/auth/sign-out','/api/auth/delete-user','/api/auth/error','/api/auth/ok']);
  if(!allowed.has(path))fail('NOT_FOUND',404);
  if(request.method==='POST'){
    requireOrigin(request);
    if(path.endsWith('/sign-in/social')){
      const body=await jsonBody(request.clone(),4096);
      if(body.provider!=='google'||body.requestSignUp!==undefined)fail('INVALID_REQUEST');
      if(body.idToken){
        if(request.headers.get('x-spdecode-mobile-auth')!=='android-v1'||
           typeof body.idToken!=='object'||typeof body.idToken.token!=='string'||
           body.idToken.token.length<200||body.idToken.token.length>10000||
           Object.keys(body.idToken).some(k=>k!=='token'))fail('INVALID_REQUEST');
      }
      if(body.acceptedTerms!=='2026-11-10'||body.acceptedPrivacy!=='2026-11-10')fail('CONSENT_REQUIRED');
    }
  }
  const response=await accountAuth().handler(request);
  response.headers.set('Cache-Control','private, no-store, max-age=0');return response;
});}
export const GET=handle;
export const POST=handle;
