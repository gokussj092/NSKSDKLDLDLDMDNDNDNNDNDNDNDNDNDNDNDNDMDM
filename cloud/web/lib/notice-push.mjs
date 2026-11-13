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
export async function pushNotice(id,{env=process.env,fetchImpl=fetch,validateOnly=false,
 priority='normal',ttlSeconds=86400,targetToken=null,privateKind=null}={}) {
  // Public topic announcements and private account tokens have distinct payload
  // types. Only authenticated backend callers can supply a device token.
  if((targetToken!==null&&!/^[A-Za-z0-9:_-]{32,512}$/.test(targetToken))||
     (privateKind!==null&&!['support','purchase','security'].includes(privateKind))||
     (targetToken===null)!==(privateKind===null))throw Error('PUSH_INVALID');
  if(!/^[0-9a-f-]{36}$/.test(id)||typeof validateOnly!=='boolean'||
    !['normal','high'].includes(priority)||!Number.isInteger(ttlSeconds)||
    ttlSeconds<0||ttlSeconds>86400)throw Error('PUSH_INVALID');
  const account=pushAccount(env);if(!account)return 'periodic';
  const targetProject=env.CLOUD_NOTICE_FCM_PROJECT_ID||account.project_id;
  if(!/^[a-z][a-z0-9-]{4,60}$/.test(targetProject))throw Error('PUSH_INVALID');
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
  const sent=await fetchImpl('https://fcm.googleapis.com/v1/projects/'+targetProject+'/messages:send',{
    method:'POST',redirect:'error',signal:AbortSignal.timeout(8000),
    headers:{'Authorization':'Bearer '+auth.access_token,'Content-Type':'application/json'},
    body:JSON.stringify({...(validateOnly?{validate_only:true}:{}),message:{
      ...(targetToken?{token:targetToken}:{topic:'spdecode-notices-v1'}),
      // Android presents the notification automatically in the background.
      // No personal messages, purchases or account data are sent to FCM.
      notification:{title:'SP-DECODE',body:privateKind==='support'?
        'Nueva respuesta de soporte':privateKind==='purchase'?
        'Actualización de tu compra':privateKind==='security'?
        'Aviso de seguridad de tu cuenta':'Nuevo aviso disponible'},
      data:privateKind?{noticeId:id,kind:'account'}:{noticeId:id},
      android:{priority,ttl:ttlSeconds+'s',
        notification:{channel_id:privateKind?'account-alerts-v1':'service-notices-chime-v2',
          tag:id}}
    }})});
  if(!sent.ok)throw Error('PUSH_UNAVAILABLE');
  return 'push';
}
