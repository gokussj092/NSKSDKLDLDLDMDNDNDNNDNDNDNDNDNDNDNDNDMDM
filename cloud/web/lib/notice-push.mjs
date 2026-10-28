import {createPrivateKey,createSign} from 'node:crypto';
const TOKEN='https://oauth2.googleapis.com/token';
const encode=value=>Buffer.from(JSON.stringify(value)).toString('base64url');
export function pushAccount(env=process.env) {
  try {
    const a=JSON.parse(env.CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON||'null');
    return a?.type==='service_account' && /^[a-z][a-z0-9-]{4,60}$/.test(a.project_id) &&
      /^[^\s@]+@[^\s@]+\.iam\.gserviceaccount\.com$/.test(a.client_email) &&
      typeof a.private_key==='string' ? a:null;
  }catch{return null;}
}
/** Sends only a wake-up hint. Notice text must be fetched with the device-bound session. */
export async function pushNotice(id,{env=process.env,fetchImpl=fetch}={}) {
  const account=pushAccount(env);if(!account)return 'periodic';
  const now=Math.floor(Date.now()/1000);
  const unsigned=encode({alg:'RS256',typ:'JWT'})+'.'+encode({iss:account.client_email,aud:TOKEN,
    scope:'https://www.googleapis.com/auth/firebase.messaging',iat:now,exp:now+300});
  const signer=createSign('RSA-SHA256');signer.update(unsigned);signer.end();
  const assertion=unsigned+'.'+signer.sign(createPrivateKey(account.private_key)).toString('base64url');
  const response=await fetchImpl(TOKEN,{method:'POST',redirect:'error',signal:AbortSignal.timeout(8000),
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion}).toString()});
  if(!response.ok)throw Error('PUSH_UNAVAILABLE');
  const auth=await response.json();
  if(typeof auth.access_token!=='string'||auth.access_token.length>8192||auth.token_type?.toLowerCase()!=='bearer')throw Error('PUSH_UNAVAILABLE');
  const sent=await fetchImpl('https://fcm.googleapis.com/v1/projects/'+account.project_id+'/messages:send',{
    method:'POST',redirect:'error',signal:AbortSignal.timeout(8000),
    headers:{'Authorization':'Bearer '+auth.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({message:{topic:'spdecode-notices-v1',data:{noticeId:id},
      android:{priority:'normal',ttl:'86400s',collapse_key:'spdecode-notices'}}})});
  if(!sent.ok)throw Error('PUSH_UNAVAILABLE');
  return 'push';
}
