import test from 'node:test';
import assert from 'node:assert/strict';
import {scryptSync,randomBytes,randomUUID} from 'node:crypto';
import {adminNotices,notificationFeedRequest,validNotice} from '../lib/app-notifications.mjs';
import {bindVerifiedRequest} from '../lib/v2-bound-request.mjs';
import {loginRequest} from '../lib/c6-admin-api.mjs';
import {pushNotice} from '../lib/notice-push.mjs';
const salt=randomBytes(16),password='notification test password 123456';
Object.assign(process.env,{CLOUD_ADMIN_ENABLED:'true',CLOUD_TRUST_PROXY:'true',CLOUD_ADMIN_USERNAME:'admin',
 CLOUD_ADMIN_PASSWORD_SCRYPT:'scrypt$16384$8$1$'+salt.toString('hex')+'$'+scryptSync(password,salt,64).toString('hex'),
 CLOUD_ADMIN_SESSION_KEY:'a'.repeat(64),CLOUD_ADMIN_PUBLIC_ORIGIN:'https://panel.example.test',CLOUD_REDIS_URL:'redis://redis:6379'});
class Redis {
 data=new Map();counts=new Map();
 async get(k){return this.data.get(k)??null;}
 async set(k,v,o={}){if(o.NX&&this.data.has(k))return null;this.data.set(k,v);return 'OK';}
 async del(k){return this.data.delete(k);}
 async incr(k){const n=(this.counts.get(k)||0)+1;this.counts.set(k,n);return n;}
 async expire(){return 1;}
 async eval(script,o){if(script.includes('spdecode:throttle:v1'))return this.incr(o.keys[0]);
  if(await this.get(o.keys[0])===o.arguments[0])return this.del(o.keys[0]);return 0;}
}
const req=(body,cookie='',action=true)=>new Request('https://panel.example.test/api/admin/notifications',{method:'POST',
 headers:{'Content-Type':'application/json',Origin:'https://panel.example.test',Cookie:cookie,...(action?{'X-SPDecode-Admin-Action':'1'}:{})},body:JSON.stringify(body)});
test('publication requires admin and CSRF; replay cannot duplicate; expired notices omitted',async()=>{
 const redis=new Redis(),options={storeProvider:async()=>redis,push:async()=>{throw Error('offline');}};
 const input={id:randomUUID(),title:'Servicio',body:'Aviso de prueba'};
 assert.equal((await adminNotices(req(input),options)).status,401);
 const login=await loginRequest(req({username:'admin',password}),{...options,turnstileVerifier:async()=>({ok:true})});
 assert.equal(login.status,200);const cookie=login.headers.get('set-cookie').split(';')[0];
 assert.equal((await adminNotices(req(input,cookie,false),options)).status,403);
 for(const bad of [{...input,url:'https://evil.test'}, {...input,title:'a'.repeat(81)}, {...input,id:'../../x'}])
  assert.equal((await adminNotices(req(bad,cookie),options)).status,400);
 const published=await adminNotices(req(input,cookie),options);assert.equal(published.status,201);
 assert.equal((await published.json()).delivery,'periodic-push-failed');
 assert.equal((await (await adminNotices(req(input,cookie),options)).json()).status,'already-published');
 const feed=()=>new Request('https://example.test/internal',{method:'POST',body:'{}'});
 assert.equal((await notificationFeedRequest(feed(),options)).status,401);
 const request=feed();bindVerifiedRequest(request,{key:'verified-server-context'});
 const body=await (await notificationFeedRequest(request,options)).json();assert.equal(body.notices.length,1);
 assert.equal(body.notices[0].body,input.body);
 assert(!validNotice({...body.notices[0],expiresAt:Date.now()-1}));
 assert(!validNotice({...body.notices[0],body:'\u202eunsafe'}));
});
test('without Firebase credentials no external request is attempted',async()=>{
 assert.equal(await pushNotice(randomUUID(),{env:{},fetchImpl:()=>{throw Error('unexpected network')}}),'periodic');
});
test('FCM uses separate OAuth scope and sends only an identifier hint to the fixed project',async()=>{
 const {generateKeyPairSync,verify}=await import('node:crypto');
 const pair=generateKeyPairSync('rsa',{modulusLength:2048}),id=randomUUID();
 const account={type:'service_account',project_id:'notice-project',client_email:'notices@notice-project.iam.gserviceaccount.com',
  private_key:pair.privateKey.export({format:'pem',type:'pkcs8'})};
 const calls=[];
 const result=await pushNotice(id,{env:{CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify(account)},fetchImpl:async(url,opts)=>{
  calls.push(url);assert.equal(opts.redirect,'error');
  if(calls.length===1) {
   assert.equal(url,'https://oauth2.googleapis.com/token');
   const jwt=new URLSearchParams(opts.body).get('assertion'),parts=jwt.split('.');
   assert(verify('RSA-SHA256',Buffer.from(parts.slice(0,2).join('.')),pair.publicKey,Buffer.from(parts[2],'base64url')));
   const claims=JSON.parse(Buffer.from(parts[1],'base64url'));
   assert.equal(claims.scope,'https://www.googleapis.com/auth/firebase.messaging');
   assert.equal(claims.exp-claims.iat,300);
   return Response.json({token_type:'Bearer',access_token:'synthetic-oauth'});
  }
  assert.equal(url,'https://fcm.googleapis.com/v1/projects/notice-project/messages:send');
  assert.equal(opts.headers.Authorization,'Bearer synthetic-oauth');
  const data=JSON.parse(opts.body);assert.deepEqual(data.message.data,{noticeId:id});
  assert.equal(data.message.topic,'spdecode-notices-v1');assert.equal(data.message.android.priority,'normal');
  assert.equal(data.message.notification,undefined);
  return Response.json({name:'synthetic-message'});
 }});
 assert.equal(result,'push');assert.equal(calls.length,2);
});
test('FCM diagnostic uses validate_only and never transmits notice text',async()=>{
 const {generateKeyPairSync}=await import('node:crypto');const pair=generateKeyPairSync('rsa',{modulusLength:2048});
 const account={type:'service_account',project_id:'sp-decode-android',client_email:'notices@sp-decode-android.iam.gserviceaccount.com',private_key:pair.privateKey.export({format:'pem',type:'pkcs8'})};
 const id=randomUUID();let calls=0;
 assert.equal(await pushNotice(id,{env:{CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify(account),CLOUD_NOTICE_FCM_PROJECT_ID:'sp-decode-android'},validateOnly:true,fetchImpl:async(url,options)=>{
  if(++calls===1)return Response.json({token_type:'Bearer',access_token:'synthetic-token'});
  assert.equal(url,'https://fcm.googleapis.com/v1/projects/sp-decode-android/messages:send');
  const body=JSON.parse(options.body);assert.equal(body.validate_only,true);assert.deepEqual(body.message.data,{noticeId:id});
  assert.equal(body.message.notification,undefined);return Response.json({});
 }}),'push');assert.equal(calls,2);
});
