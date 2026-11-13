import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {encryptPushToken,decryptPushToken,registerPush,unregisterPush,
 recordAccountNotice,pushAccountNotice,accountNoticeFeed,markAccountNotice}
 from '../lib/commerce/account-notices.mjs';
import {activityFor} from '../lib/commerce/account-activity.mjs';
let pg,db,auth;
const ids=[randomUUID(),randomUUID()],token='fcm_token:APA91_'+('A'.repeat(120));
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://test',
 BETTER_AUTH_SECRET:'notices-private-test-secret-'.repeat(3),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_SUPPORT_ENCRYPTION_KEY:randomBytes(32).toString('hex')};
Object.assign(process.env,env);
before(async()=>{
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','003_ads_free.sql','004_gifts.sql',
  '005_account_support_apk.sql','006_support_agent_identity.sql',
  '007_staff_permissions.sql','008_account_notifications.sql']){
  await pg.exec(await readFile(new URL('../sql/'+name,import.meta.url),'utf8'));
 }
 for(const [i,id] of ids.entries()){
  await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,
  [id,'Push QA '+i,id+'@example.invalid']);
 }
});
after(async()=>{await pg?.close();});
test('FCM tokens are encrypted and bound to one account',()=>{
 const item=encryptPushToken(ids[0],token,env);
 assert.equal(item.ciphertext.includes(token),false);
 assert.match(item.digest,/^[a-f0-9]{64}$/);
 assert.equal(decryptPushToken(ids[0],item.ciphertext,env),token);
 assert.throws(()=>decryptPushToken(ids[1],item.ciphertext,env),/PUSH_TOKEN_UNAVAILABLE/);
 assert.throws(()=>decryptPushToken(ids[0],item.ciphertext.slice(0,-4)+'AAAA',env),/PUSH_TOKEN_UNAVAILABLE/);
 assert.throws(()=>encryptPushToken(ids[0],token,{SPDECODE_SUPPORT_ENCRYPTION_KEY:'invalid'}),/PUSH_NOT_CONFIGURED/);
});
test('FCM registration is scoped and a device can switch accounts without receiving old notices',async()=>{
 await registerPush(ids[0],token,{db,env});
 let row=(await db.query('SELECT account_id,token_ciphertext FROM spdecode_shop.account_push_devices')).rows;
 assert.equal(row.length,1);assert.equal(row[0].account_id,ids[0]);
 assert.equal(row[0].token_ciphertext.includes(token),false);
 await registerPush(ids[1],token,{db,env});
 row=(await db.query('SELECT account_id FROM spdecode_shop.account_push_devices')).rows;
 assert.equal(row.length,1);assert.equal(row[0].account_id,ids[1]);
 await unregisterPush(ids[0],token,{db,env});
 assert.equal((await db.query('SELECT account_id FROM spdecode_shop.account_push_devices')).rowCount,1);
});
test('private inbox has account-scoped reads, de-duplication and silent push fallback',async()=>{
 const id=await recordAccountNotice(db,ids[1],'support:sample-qa','support',randomUUID());
 assert.match(id,/^[0-9a-f-]{36}$/);
 assert.equal(await recordAccountNotice(db,ids[1],'support:sample-qa','support',randomUUID()),null);
 assert.equal((await accountNoticeFeed(ids[0],{db})).unread,0);
 const owner=await accountNoticeFeed(ids[1],{db});
 assert.equal(owner.unread,1);
 assert.equal(owner.notices[0].id,id);
 await assert.rejects(markAccountNotice(ids[0],id,{db}),/NOTICE_NOT_FOUND/);
 let seen=0;
 const delivered=await pushAccountNotice(ids[1],id,'support',{db,env,
  send:async (_id,args)=>{
   assert.equal(args.targetToken,token);
   assert.equal(args.privateKind,'support');
   assert.equal(args.priority,'high');
   seen++;return 'push';
  }});
 assert.equal(delivered.queued,1);assert.equal(seen,1);
 const other=await pushAccountNotice(ids[0],id,'support',{db,env,
  send:async()=>{throw Error('Other user device should not receive push')}});
 assert.equal(other.queued,0);
 await markAccountNotice(ids[1],id,{db});
 assert.equal((await accountNoticeFeed(ids[1],{db})).unread,0);
});
test('activity history only returns purchases, credits and analyses for the owner',async()=>{
 await db.query(`INSERT INTO spdecode_shop.credit_ledger
  (id,account_id,movement_kind,delta,payment_live) VALUES($1,$2,'grant',4,false)`,
  [randomUUID(),ids[0]]);
 await db.query(`INSERT INTO spdecode_shop.apk_qa_jobs
  (job_id,account_id,device_key_hash,payment_live)
  VALUES($1,$2,$3,false)`,[randomUUID(),ids[0],'a'.repeat(64)]);
 const a=await activityFor(ids[0],{db,live:false});
 const b=await activityFor(ids[1],{db,live:false});
 assert.ok(a.operations.some(x=>x.kind==='credit'&&x.delta===4));
 assert.ok(a.operations.some(x=>x.kind==='analysis'));
 assert.equal(b.operations.filter(x=>x.kind==='credit'||x.kind==='analysis').length,0);
});
