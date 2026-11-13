import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {createSupportThread,sendSupportMessage,listUserSupport,listAdminSupport,
 replyAdminSupport,encryptMessage,decryptMessage} from '../lib/commerce/support.mjs';
import {registerDevice,makeDeletionChallenge,authorizeDeviceDeletion,
 deleteAccountData} from '../lib/commerce/account-device.mjs';
let pg,db,auth;
const ids=[randomUUID(),randomUUID()];
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:'support-qa-secret-'.repeat(3),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_SUPPORT_ENCRYPTION_KEY:randomBytes(32).toString('hex')};
Object.assign(process.env,env);
before(async()=>{
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','003_ads_free.sql','004_gifts.sql','005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql']){
  const sql=await readFile(new URL('../sql/'+name,import.meta.url),'utf8');
  await pg.exec(sql);
 }
 for(const [i,id] of ids.entries()){
  await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
   VALUES($1,$2,$3,true,now(),now())`,[id,'Support User '+i,id+'@example.invalid']);
 }
});
after(async()=>{await pg?.close();});
test('AES-256-GCM messages are bound to thread+sender and rejected on tampering',()=>{
 const thread=randomUUID(),id=randomUUID(),text='Private support inquiry with credentials omitted';
 const ciphertext=encryptMessage(thread,id,'user',text,{env});
 assert.equal(ciphertext.includes(text),false);
 const row={id,thread_id:thread,sender_kind:'user',ciphertext};
 assert.equal(decryptMessage(row,{env}),text);
 assert.throws(()=>decryptMessage({...row,sender_kind:'admin'},{env}),/SUPPORT_MESSAGE_UNAVAILABLE/);
 assert.throws(()=>decryptMessage({...row,ciphertext:ciphertext.slice(0,-4)+'AAAA'},{env}),/SUPPORT_MESSAGE_UNAVAILABLE/);
});
test('private inbox, reply, status and distinct-account ACL',async()=>{
 const thread=await createSupportThread(ids[0],{subject:'Decoder failure',
  category:'apk',message:'Unexpected result from recent APK'},{db,env});
 const messages=(await db.query('SELECT ciphertext FROM spdecode_shop.support_messages WHERE thread_id=$1',[thread.id])).rows;
 assert.equal(messages.length,1);
 assert.equal(messages[0].ciphertext.includes('Unexpected result'),false);
 const other=await listUserSupport(ids[1],{db,env});assert.equal(other.threads.length,0);
 await assert.rejects(sendSupportMessage(ids[1],thread.id,{message:'Intrusion'},{db,env}),/SUPPORT_NOT_FOUND/);
 await replyAdminSupport({id:'admin-test',name:'Operator QA',role:'admin'},
   {threadId:thread.id,action:'reply',message:'We will investigate.'},{db,env});
 await sendSupportMessage(ids[0],thread.id,{message:'Thank you'},{db,env});
 const owner=await listUserSupport(ids[0],{db,env});
 assert.deepEqual(owner.threads[0].messages.map(x=>x.sender),['user','admin','user']);
 assert.equal(owner.threads[0].messages[1].text,'We will investigate.');
 assert.equal(owner.threads[0].messages[1].agent.name,'Operator QA');
 assert.equal(owner.threads[0].messages[1].agent.role,'admin');
 const admin=await listAdminSupport({db,env});
 assert.equal(admin.threads[0].account_id,ids[0]);
 await replyAdminSupport('admin-test',{threadId:thread.id,action:'close'},{db,env});
 await assert.rejects(sendSupportMessage(ids[0],thread.id,{message:'More?'},{db,env}),/SUPPORT_THREAD_CLOSED/);
});
test('AndroidKeyStore-compatible P256 signatures require account binding and one-time challenge',async()=>{
 const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const keyId=randomUUID(),publicEncoded=publicKey.export({format:'der',type:'spki'}).toString('base64url');
 const signText=text=>sign('sha256',Buffer.from(text),privateKey).toString('base64url');
 const registration='SPDECODE-DEVICE-REGISTER-v1:'+ids[1]+':'+keyId;
 await registerDevice(ids[1],{keyId,publicKey:publicEncoded,signature:signText(registration)},{db});
 await assert.rejects(registerDevice(ids[0],{keyId,publicKey:publicEncoded,
  signature:signText(registration)},{db}),/DEVICE_SIGNATURE_INVALID/);
 const challenge=await makeDeletionChallenge(ids[1],keyId,{db});
 assert.match(challenge.challenge,/^SPDECODE-DELETE-v1:/);
 await assert.rejects(authorizeDeviceDeletion(ids[0],{...challenge,keyId,
   signature:signText(challenge.challenge)},{db}),/CHALLENGE_EXPIRED/);
 await authorizeDeviceDeletion(ids[1],{...challenge,keyId,
  signature:signText(challenge.challenge)},{db});
 await assert.rejects(authorizeDeviceDeletion(ids[1],{...challenge,keyId,
  signature:signText(challenge.challenge)},{db}),/CHALLENGE_EXPIRED/);
});
test('confirmed deletion removes account and private messages',async()=>{
 await deleteAccountData(ids[1],{db});
 const user=await db.query('SELECT id FROM shop_user WHERE id=$1',[ids[1]]);
 assert.equal(user.rowCount,0);
 const inbox=await db.query('SELECT id FROM spdecode_shop.support_threads WHERE account_id=$1',[ids[1]]);
 assert.equal(inbox.rowCount,0);
});
