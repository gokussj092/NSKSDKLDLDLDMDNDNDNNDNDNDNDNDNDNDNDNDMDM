import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,randomUUID,generateKeyPairSync} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {adminPushAccount,pushAdminNotice,pushNotice} from '../lib/notice-push.mjs';
import {recordAdminNotice,adminInbox,registerAdminPush,pushAdminRecipientNotice,adminRecipient,adminInboxRequest} from '../lib/commerce/admin-notices.mjs';
import {ShopError} from '../lib/commerce/config.mjs';
import {registerPush,recordAccountNotice,pushAccountNotice,decryptPushToken} from '../lib/commerce/account-notices.mjs';
import {writeStoredFeed,readStoredFeed,readAdministrativeQuarantine} from '../lib/notice-store.mjs';
import {notificationFeedRequest} from '../lib/app-notifications.mjs';
import {bindVerifiedRequest} from '../lib/v2-bound-request.mjs';

let pg,db,root;
const ids=[randomUUID(),randomUUID()],staffId=randomUUID();
const tokenA='device_A:'+'A'.repeat(100),tokenB='device_B:'+'B'.repeat(100),adminToken='admin_device:'+'C'.repeat(100);
const account=project=>({type:'service_account',project_id:project,client_email:'push@'+project+'.iam.gserviceaccount.com',
 private_key:generateKeyPairSync('rsa',{modulusLength:2048}).privateKey.export({format:'pem',type:'pkcs8'})});
const online=account('online-notices-test'),admin=account('admin-notices-test');
const env={NODE_ENV:'test',SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:'notification-isolation-'.repeat(3),CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 GOOGLE_CLIENT_ID:'synthetic',GOOGLE_CLIENT_SECRET:'synthetic',SPDECODE_SUPPORT_ENCRYPTION_KEY:randomBytes(32).toString('hex'),
 CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify(online),CLOUD_NOTICE_FCM_PROJECT_ID:online.project_id,
 CLOUD_ADMIN_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify(admin),CLOUD_ADMIN_FCM_PROJECT_ID:admin.project_id,
 CLOUD_NOTICE_STORE_PATH:'/app/notices/feed.json'};
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'notice-isolation-'));pg=new PGlite();
 const query=async(sql,args=[])=>{const r=await pg.query(sql,args);return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};};
 db={query,connect:async()=>({query,release(){}})};
 await (await getMigrations(makeAuth(db,env).options)).runMigrations();
 for(const name of ['002_shop.sql','005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql','008_account_notifications.sql','016_private_admin_notices.sql'])
  await pg.exec(await readFile(new URL('../sql/'+name,import.meta.url),'utf8'));
 for(const id of ids)await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt") VALUES($1,'Synthetic',$2,true,now(),now())`,[id,id+'@example.invalid']);
});
after(async()=>{await pg?.close();await rm(root,{recursive:true,force:true});});

test('Admin rejects missing or reused Firebase credentials without any network request',async()=>{
 for(const config of [{...env,CLOUD_ADMIN_FCM_SERVICE_ACCOUNT_JSON:''},
  {...env,CLOUD_ADMIN_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify(online)},
  {...env,CLOUD_ADMIN_FCM_PROJECT_ID:online.project_id},
  {...env,CLOUD_ADMIN_FCM_SERVICE_ACCOUNT_JSON:JSON.stringify({...admin,private_key:online.private_key})}]){
  assert.equal(adminPushAccount(config),null);
  assert.equal(await pushAdminNotice(randomUUID(),{env:config,targetToken:adminToken,privateKind:'support',
   fetchImpl:()=>{throw Error('MUST_NOT_CONTACT_FCM');}}),'periodic');
 }
 await assert.rejects(pushAdminNotice(randomUUID(),{env}),/PUSH_INVALID/);
});
test('Admin targets one token in its own project and package; Online keeps its public topic',async()=>{
 for(const isAdmin of [true,false]){
  let count=0;
  const result=await (isAdmin?pushAdminNotice:pushNotice)(randomUUID(),{env,...(isAdmin?{targetToken:adminToken,privateKind:'support'}:{}),
   fetchImpl:async(url,opts)=>{
    if(++count===1)return Response.json({token_type:'Bearer',access_token:'synthetic'});
    assert.equal(url,'https://fcm.googleapis.com/v1/projects/'+(isAdmin?admin.project_id:online.project_id)+'/messages:send');
    const msg=JSON.parse(opts.body).message;
    assert.equal(msg.android.restricted_package_name,isAdmin?'com.ghostdeveloper.spdecode.admin':'com.ghostdeveloper.spdecode');
    if(isAdmin){assert.equal(msg.token,adminToken);assert.equal(msg.topic,undefined);assert.equal(msg.condition,undefined);
     assert.equal(msg.data.kind,'admin');assert.equal(msg.notification.title,'SP-DECODE Admin');}
    else{assert.equal(msg.topic,'spdecode-notices-v1');assert.equal(msg.token,undefined);}
    return Response.json({name:'synthetic'});
   }});
  assert.equal(result,'push');assert.equal(count,2);
 }
});
test('private user events require matching account and event kind, even when both users have tokens',async()=>{
 await registerPush(ids[0],tokenA,{db,env});await registerPush(ids[1],tokenB,{db,env});
 const id=await recordAccountNotice(db,ids[0],'support:isolation','support');
 const sent=[];const send=async(notice,args)=>{sent.push(args.targetToken);assert.equal(args.privateKind,'support');return 'push';};
 assert.equal((await pushAccountNotice(ids[0],id,'support',{db,env,send})).queued,1);
 assert.deepEqual(sent,[tokenA]);
 assert.equal((await pushAccountNotice(ids[1],id,'support',{db,env,send})).queued,0);
 assert.equal((await pushAccountNotice(ids[0],id,'purchase',{db,env,send})).queued,0);
 assert.deepEqual(sent,[tokenA]);
});
test('Admin inboxes and token ownership cannot cross recipients or the Online token table',async()=>{
 const id=randomUUID();await recordAdminNotice(db,{id,recipientId:'owner',kind:'support_escalation'});
 await registerAdminPush('owner',adminToken,{db,env});
 const rows=(await db.query('SELECT token_ciphertext FROM spdecode_shop.admin_push_devices')).rows;
 assert.throws(()=>decryptPushToken('owner',rows[0].token_ciphertext,env),/PUSH_TOKEN_UNAVAILABLE/);
 assert.equal((await adminInbox(staffId,{db,env,root})).notices.length,0);
 assert.equal((await adminInbox('owner',{db,env,root})).notices[0].title,'Soporte escalado a Ghost Developer');
 const sent=[];const send=async(n,args)=>{sent.push(args.targetToken);return 'push';};
 assert.equal((await pushAdminRecipientNotice('owner',id,{db,env,send})).queued,1);
 assert.deepEqual(sent,[adminToken]);
 assert.equal((await pushAdminRecipientNotice(staffId,id,{db,env,send})).queued,0);
 await registerAdminPush(staffId,adminToken,{db,env}); // Account switch revokes the previous recipient.
 assert.equal((await pushAdminRecipientNotice('owner',id,{db,env,send})).queued,0);
 assert.deepEqual(sent,[adminToken]);
 assert.equal(adminRecipient({role:'owner',id:'owner-session'}),'owner');
 assert.throws(()=>adminRecipient({role:'support',id:staffId,mustChangePassword:true}),/FORBIDDEN/);
});
test('legacy administrative notices are quarantined and canonicalized, never returned to Online',async()=>{
 const now=Date.now(),base={createdAt:now,expiresAt:now+86400000,type:'general',importance:'normal',delivery:'poll'};
 const general={...base,id:randomUUID(),title:'Catálogo actualizado',body:'Aviso público'};
 const internal={...base,id:randomUUID(),title:'Soporte escalado a nombre anterior',body:'Un hilo de soporte fue escalado y necesita tu intervención.'};
 await writeStoredFeed([general,internal],{root,env});
 const redis={get:async()=>null};
 const request=new Request('https://example.invalid/api/v2',{method:'POST',body:'{}'});
 bindVerifiedRequest(request,{key:'verified'});
 const response=await notificationFeedRequest(request,{storeProvider:async()=>redis,storageOptions:{root,env}});
 assert.equal(response.status,200);assert.deepEqual((await response.json()).notices.map(n=>n.id),[general.id]);
 assert.deepEqual((await readStoredFeed({root,env})).map(n=>n.id),[general.id]);
 const quarantine=await readAdministrativeQuarantine({root,env});assert.equal(quarantine[0].title,'Soporte escalado a Ghost Developer');
 assert.equal((await readFile(join(root,'admin-quarantine.json'),'utf8')).includes('nombre anterior'),false);
 const inbox=await adminInbox('owner',{db,env,root});assert(inbox.notices.some(n=>n.id===internal.id));
});
test('private Admin API derives its recipient from the session and rejects recipient overrides',async()=>{
 process.env.CLOUD_ADMIN_PUBLIC_ORIGIN='https://panel.example.invalid';
 const endpoint='https://panel.example.invalid/api/admin/notifications/inbox';
 const deny=await adminInboxRequest(new Request(endpoint),{authorize:async()=>{throw new ShopError('UNAUTHORIZED',401);}});
 assert.equal(deny.status,401);
 const options={db,env,root,authorize:async(req,permission)=>{
  assert.equal(permission,'support.read');return {id:staffId,role:'support'};
 }};
 const response=await adminInboxRequest(new Request(endpoint+'?recipientId=owner'),options);
 assert.equal(response.status,200);assert.equal((await response.json()).notices.length,0);
 const mutation=(body,csrf=true)=>new Request(endpoint,{method:'POST',headers:{'content-type':'application/json',
  Origin:'https://panel.example.invalid',...(csrf?{'x-spdecode-admin-action':'1'}:{})},body:JSON.stringify(body)});
 assert.equal((await adminInboxRequest(mutation({action:'register',token:adminToken,recipientId:'owner'}),options)).status,400);
 assert.equal((await adminInboxRequest(mutation({action:'register',token:adminToken},false),options)).status,403);
 const id=(await db.query("SELECT id FROM spdecode_shop.admin_notices WHERE recipient_id='owner' LIMIT 1")).rows[0].id;
 assert.equal((await adminInboxRequest(mutation({action:'read',id}),options)).status,404);
});
test('active internal events deduplicate but a later message can renew an expired event',async()=>{
 const id=randomUUID(),event={id,recipientId:'owner',kind:'support_message'};
 assert.equal(await recordAdminNotice(db,event),id);
 assert.equal(await recordAdminNotice(db,event),null);
 await db.query("UPDATE spdecode_shop.admin_notices SET expires_at=now()-interval '1 second',read_at=now() WHERE id=$1",[id]);
 assert.equal(await recordAdminNotice(db,event),id);
 const row=(await db.query('SELECT read_at,expires_at FROM spdecode_shop.admin_notices WHERE id=$1',[id])).rows[0];
 assert.equal(row.read_at,null);assert(new Date(row.expires_at)>new Date());
 assert.equal(await recordAdminNotice(db,event),null);
});
