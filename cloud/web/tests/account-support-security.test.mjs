import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID,generateKeyPairSync,sign,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {readStoredFeed} from '../lib/notice-store.mjs';
import {createSupportThread,sendSupportMessage,listUserSupport,listAdminSupport,
 replyAdminSupport,markSupportThreadRead,encryptMessage,decryptMessage,
 liftSupportSuspension,escalateSupportThread,findAutoAssignStaffId,
 escalationNoticeId,newSupportMessageNoticeId} from '../lib/commerce/support.mjs';
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
 for(const name of ['002_shop.sql','003_ads_free.sql','004_gifts.sql','005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql','008_account_notifications.sql','009_staff_custom_roles.sql','010_support_reads_avatar.sql','011_support_autoassign_reads_antispam.sql','013_support_escalation.sql']){
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
test('unread counters, mark-as-read and agent avatar snapshot',async()=>{
 const bytes=Buffer.alloc(100);bytes[0]=0xff;bytes[1]=0xd8;bytes[98]=0xff;bytes[99]=0xd9;
 const avatar='data:image/jpeg;base64,'+bytes.toString('base64');
 const thread=await createSupportThread(ids[0],{subject:'Unread check',
  category:'technical',message:'First message'},{db,env});
 const unreadOf=(listing,id)=>listing.threads.find(t=>t.id===id)?.unread;
 // Staff side: the new user message is unread; user side: nothing to read yet.
 let admin=await listAdminSupport({db,env});
 assert.equal(unreadOf(admin,thread.id),1);
 assert.equal(admin.unreadTotal,admin.threads.reduce((n,t)=>n+t.unread,0));
 let user=await listUserSupport(ids[0],{db,env});
 assert.equal(unreadOf(user,thread.id),0);
 // ACL on mark-as-read: another user sees nothing; unassigned staff is refused.
 await assert.rejects(markSupportThreadRead(thread.id,{kind:'user',id:ids[1]},{db}),/SUPPORT_NOT_FOUND/);
 await assert.rejects(markSupportThreadRead(thread.id,{kind:'staff',id:randomUUID()},{db}),/SUPPORT_NOT_ASSIGNED/);
 await assert.rejects(markSupportThreadRead(randomUUID(),{kind:'user',id:ids[0]},{db}),/SUPPORT_NOT_FOUND/);
 // Staff marks the thread read: only that thread clears, other threads keep theirs.
 // (The read state is per actor, so the listing must run as that staff member.)
 await markSupportThreadRead(thread.id,{kind:'staff',id:'f'.repeat(64),canSeeAll:true},{db});
 admin=await listAdminSupport({db,env,principal:{id:'f'.repeat(64),
   capabilities:['support.read','support.assign']}});
 assert.equal(unreadOf(admin,thread.id),0);
 // Admin reply with avatar: user sees 1 unread and the avatar snapshot on the message.
 await replyAdminSupport({id:'f'.repeat(64),name:'Operator QA',role:'owner',avatar},
   {threadId:thread.id,action:'reply',message:'Checking it.'},{db,env});
 user=await listUserSupport(ids[0],{db,env});
 assert.equal(unreadOf(user,thread.id),1);
 assert.equal(user.unreadTotal,user.threads.reduce((n,t)=>n+t.unread,0));
 assert.equal(user.threads.find(t=>t.id===thread.id).messages.at(-1).agent.avatar,avatar);
 assert.equal(user.threads.find(t=>t.id===thread.id).messages.at(-1).agent.name,'Operator QA');
 // User marks read: the thread clears; a reply without avatar emits null.
 await markSupportThreadRead(thread.id,{kind:'user',id:ids[0]},{db});
 user=await listUserSupport(ids[0],{db,env});
 assert.equal(unreadOf(user,thread.id),0);
 await replyAdminSupport({id:'f'.repeat(64),name:'Operator QA',role:'owner'},
   {threadId:thread.id,action:'reply',message:'No avatar here.'},{db,env});
 user=await listUserSupport(ids[0],{db,env});
 assert.equal(user.threads.find(t=>t.id===thread.id).messages.at(-1).agent.avatar,null);
 // Invalid avatars are rejected before any message is stored.
 await assert.rejects(replyAdminSupport({id:'f'.repeat(64),name:'Operator QA',role:'owner',avatar:'data:image/png;base64,AAAA'},
   {threadId:thread.id,action:'reply',message:'Bad avatar'},{db,env}),/INVALID_AVATAR/);
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
test('one open ticket, 4th ticket of the day suspends support for 1h, lift restores it',async()=>{
 const userId=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,[userId,'Spam QA',userId+'@example.invalid']);
 const mk=subject=>createSupportThread(userId,{subject,category:'technical',
  message:'Help with '+subject},{db,env});
 const t1=await mk('First issue');
 const t2=await mk('Second issue');
 // A new thread closes the previous open one: only one stays open (D4).
 let listing=await listUserSupport(userId,{db,env});
 assert.equal(listing.threads.find(t=>t.id===t1.id).status,'closed');
 assert.equal(listing.threads.find(t=>t.id===t2.id).status,'open');
 assert.equal(listing.suspension,null);
 await mk('Third issue');
 assert.equal((await listUserSupport(userId,{db,env})).suspension,null);
 // The 4th thread of the day is created AND suspends support for 1 hour.
 const t4=await mk('Fourth issue');
 assert.ok(t4.suspendedUntil);
 assert.ok(new Date(t4.suspendedUntil).getTime()>Date.now());
 assert.ok(new Date(t4.suspendedUntil).getTime()<=Date.now()+3600_000+5000);
 listing=await listUserSupport(userId,{db,env});
 assert.equal(listing.suspension?.reason,'too_many_tickets');
 assert.equal(listing.suspension?.suspendedUntil,t4.suspendedUntil);
 // Suspended: new threads and messages fail with 429 SUPPORT_SUSPENDED
 // carrying the suspension end.
 await assert.rejects(mk('Fifth issue'),e=>e.code==='SUPPORT_SUSPENDED'&&e.status===429&&
  typeof e.details?.suspendedUntil==='string');
 await assert.rejects(sendSupportMessage(userId,t4.id,{message:'Still there?'},{db,env}),
  e=>e.code==='SUPPORT_SUSPENDED'&&e.status===429);
 // The admin list shows the suspension on the thread, no priors yet.
 const admin=await listAdminSupport({db,env});
 const row=admin.threads.find(t=>t.id===t4.id);
 assert.equal(row.suspension?.reason,'too_many_tickets');
 assert.equal(row.suspension?.priorCount,0);
 // Lift by a support-role staff member restores access; a second lift is a no-op.
 const support={id:randomUUID(),role:'support',capabilities:['support.read','support.write']};
 assert.deepEqual(await liftSupportSuspension(support,userId,{db}),{lifted:true});
 assert.equal((await listUserSupport(userId,{db,env})).suspension,null);
 assert.deepEqual(await liftSupportSuspension(support,userId,{db}),{lifted:false});
 await sendSupportMessage(userId,t4.id,{message:'Back again'},{db,env});
 // Creating another thread the same day suspends again; the lifted one counts as prior.
 const t5=await mk('Fifth issue');
 assert.ok(t5.suspendedUntil);
 const admin2=await listAdminSupport({db,env});
 assert.equal(admin2.threads.find(t=>t.id===t5.id).suspension?.priorCount,1);
 // Without support.write the lift is refused.
 await assert.rejects(liftSupportSuspension({id:randomUUID(),role:'billing',
  capabilities:['users.read','billing.read']},userId,{db}),/INVALID_REQUEST/);
});
test('staff read receipt and inactivity close only when staff spoke last',async()=>{
 const userId=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,[userId,'Reads QA',userId+'@example.invalid']);
 const thread=await createSupportThread(userId,{subject:'Read receipt',
  category:'apk',message:'Hello'},{db,env});
 let listing=await listUserSupport(userId,{db,env});
 assert.equal(listing.threads[0].staffReadAt,null);
 await markSupportThreadRead(thread.id,{kind:'staff',id:randomUUID(),canSeeAll:true},{db});
 listing=await listUserSupport(userId,{db,env});
 assert.ok(listing.threads[0].staffReadAt);
 assert.ok(new Date(listing.threads[0].staffReadAt).getTime()<=Date.now());
 // Last message is from the user: 2h of silence does not close the thread.
 await db.query(`UPDATE spdecode_shop.support_threads SET last_message_at=now()-interval '2 hours' WHERE id=$1`,[thread.id]);
 listing=await listUserSupport(userId,{db,env});
 assert.equal(listing.threads[0].status,'open');
 // Staff replies and 2h pass with no user answer: the next list closes it.
 await replyAdminSupport({id:'f'.repeat(64),name:'Operator QA',role:'owner'},
  {threadId:thread.id,action:'reply',message:'Looking into it.'},{db,env});
 await db.query(`UPDATE spdecode_shop.support_threads SET last_message_at=now()-interval '2 hours' WHERE id=$1`,[thread.id]);
 listing=await listUserSupport(userId,{db,env});
 assert.equal(listing.threads[0].status,'closed');
});
test('confirmed deletion removes account and private messages',async()=>{
 await deleteAccountData(ids[1],{db});
 const user=await db.query('SELECT id FROM shop_user WHERE id=$1',[ids[1]]);
 assert.equal(user.rowCount,0);
 const inbox=await db.query('SELECT id FROM spdecode_shop.support_threads WHERE account_id=$1',[ids[1]]);
 assert.equal(inbox.rowCount,0);
});
let yamadaStaffId=null;
async function mkStaff(username,displayName){
 const id=randomUUID();
 await db.query(`INSERT INTO spdecode_shop.staff_accounts
  (id,username,display_name,role,password_hash,enabled,must_change_password)
  VALUES($1,$2,$3,'support',$4,true,false)`,[id,username,displayName,'0'.repeat(64)]);
 return id;
}
async function mkUser(){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,[id,'Escalation QA',id+'@example.invalid']);
 return id;
}
test('auto-assignment finds Yamada case-insensitively',async()=>{
 yamadaStaffId=await mkStaff('yamada','Yamada');
 assert.equal(await findAutoAssignStaffId(db,env),yamadaStaffId);
 assert.equal(await findAutoAssignStaffId(db,{...env,
  SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'yamada'}),yamadaStaffId);
 assert.equal(await findAutoAssignStaffId(db,{...env,
  SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'YAMADA'}),yamadaStaffId);
 assert.equal(await findAutoAssignStaffId(db,{...env,
  SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'Pedro'}),null);
 await db.query(`UPDATE spdecode_shop.staff_accounts SET enabled=false WHERE id=$1`,
  [yamadaStaffId]);
 assert.equal(await findAutoAssignStaffId(db,env),null);
 await db.query(`UPDATE spdecode_shop.staff_accounts SET enabled=true WHERE id=$1`,
  [yamadaStaffId]);
 assert.equal(await findAutoAssignStaffId(db,env),yamadaStaffId);
});
test('escalation notice id is a stable v4 UUID per thread',()=>{
 const id=randomUUID();
 assert.match(escalationNoticeId(id),
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 assert.equal(escalationNoticeId(id),escalationNoticeId(id));
 assert.notEqual(escalationNoticeId(id),escalationNoticeId(randomUUID()));
});
test('escalation to Pedro: assigned agent escalates, owner sees the mark, idempotent',async()=>{
 const otherId=await mkStaff('helper','Helper');
 const yamada={id:yamadaStaffId,role:'support',capabilities:['support.read','support.write']};
 const other={id:otherId,role:'support',capabilities:['support.read','support.write']};
 const owner={id:'o'.repeat(64),role:'owner',
  capabilities:['staff.read','staff.write','users.read','support.read','support.write',
   'support.assign','audit.read','billing.read']};
 const billing={id:randomUUID(),role:'billing',capabilities:['users.read','billing.read']};
 const userA=await mkUser(),userB=await mkUser();
 const thread=await createSupportThread(userA,{subject:'Escalation check',
  category:'technical',message:'Please help'},{db,env});
 assert.equal(thread.assignedStaffId,yamadaStaffId);
 // Another support agent who is not assigned cannot escalate.
 await assert.rejects(escalateSupportThread(other,{action:'escalate',threadId:thread.id},{db,env}),/SUPPORT_NOT_ASSIGNED/);
 // Staff without any support capability is refused outright.
 await assert.rejects(escalateSupportThread(billing,{action:'escalate',threadId:thread.id},{db,env}),/FORBIDDEN/);
 // Unknown thread.
 await assert.rejects(escalateSupportThread(yamada,{action:'escalate',threadId:randomUUID()},{db,env}),/SUPPORT_NOT_FOUND/);
 // Malformed input.
 await assert.rejects(escalateSupportThread(yamada,{action:'escalate',threadId:thread.id,extra:1},{db,env}),/INVALID_REQUEST/);
 // Yamada escalates his own thread: high priority + mark + one audit row.
 const first=await escalateSupportThread(yamada,{action:'escalate',threadId:thread.id},{db,env});
 assert.equal(first.saved,true);
 assert.equal(first.escalated,true);
 assert.equal(first.alreadyEscalated,false);
 assert.equal(first.thread.priority,'high');
 assert.equal(first.thread.escalatedBy,yamadaStaffId);
 assert.ok(Date.parse(first.thread.escalatedAt)<=Date.now());
 const audit=(await db.query(`SELECT action,actor_id FROM spdecode_shop.staff_audit
  WHERE target_id=$1 AND action='support_escalated'`,[thread.id])).rows;
 assert.equal(audit.length,1);
 assert.equal(audit[0].actor_id,yamadaStaffId);
 // The owner sees the escalated thread with its mark (canSeeAll).
 const listing=await listAdminSupport({db,env,principal:owner});
 const row=listing.threads.find(t=>t.id===thread.id);
 assert.equal(row.priority,'high');
 assert.ok(row.escalated_at);
 assert.equal(row.escalated_by,yamadaStaffId);
 // Idempotent: a second escalation changes nothing and adds no audit row.
 const second=await escalateSupportThread(yamada,{action:'escalate',threadId:thread.id},{db,env});
 assert.equal(second.alreadyEscalated,true);
 assert.equal(second.thread.priority,'high');
 const audit2=(await db.query(`SELECT id FROM spdecode_shop.staff_audit
  WHERE target_id=$1 AND action='support_escalated'`,[thread.id])).rows;
 assert.equal(audit2.length,1);
 // The owner can escalate a fresh thread even when it is not assigned to them.
 const threadB=await createSupportThread(userB,{subject:'Owner escalation',
  category:'payments',message:'Needs Pedro'},{db,env});
 assert.equal(threadB.assignedStaffId,yamadaStaffId);
 const third=await escalateSupportThread(owner,{action:'escalate',threadId:threadB.id},{db,env});
 assert.equal(third.alreadyEscalated,false);
 assert.equal(third.thread.priority,'high');
 assert.equal(third.thread.escalatedBy,owner.id);
});
const noticeEnv={...env,CLOUD_NOTICE_STORE_PATH:'/app/notices/feed.json'};
test('new-user-message notice id is a stable v4 UUID per thread',()=>{
 const id=randomUUID();
 assert.match(newSupportMessageNoticeId(id),
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
 assert.equal(newSupportMessageNoticeId(id),newSupportMessageNoticeId(id));
 assert.notEqual(newSupportMessageNoticeId(id),newSupportMessageNoticeId(randomUUID()));
 assert.notEqual(newSupportMessageNoticeId(id),escalationNoticeId(id));
});
test('new user message publishes one notice per thread; staff reply adds none',async()=>{
 const root=await mkdtemp(join(tmpdir(),'support-notice-'));
 try{
  const user=await mkUser();
  const thread=await createSupportThread(user,{subject:'Notice check',
   category:'technical',message:'My VPN fails on login'},{db,env:noticeEnv,noticeRoot:root});
  let feed=await readStoredFeed({root,env:noticeEnv});
  assert.equal(feed.length,1);
  assert.equal(feed[0].id,newSupportMessageNoticeId(thread.id));
  assert.equal(feed[0].title,'Nuevo mensaje de soporte');
  assert.equal(feed[0].body,'Un usuario escribió en soporte y necesita respuesta.');
  assert.equal(feed[0].body.includes('My VPN fails'),false);
  assert.equal(feed[0].type,'general');
  assert.equal(feed[0].importance,'normal');
  assert.equal(feed[0].delivery,'poll');
  assert.equal(feed[0].expiresAt-feed[0].createdAt,24*3600000);
  // A user follow-up in the same thread does not duplicate the notice.
  await sendSupportMessage(user,thread.id,{message:'Still failing'},{db,env:noticeEnv,noticeRoot:root});
  feed=await readStoredFeed({root,env:noticeEnv});
  assert.equal(feed.length,1);
  assert.equal(feed[0].id,newSupportMessageNoticeId(thread.id));
  // A staff reply publishes no new-message notice either.
  await replyAdminSupport({id:yamadaStaffId,name:'Yamada',role:'support'},
   {threadId:thread.id,action:'reply',message:'Checking it.'},{db,env});
  feed=await readStoredFeed({root,env:noticeEnv});
  assert.equal(feed.length,1);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('notice store failure never blocks a user message',async()=>{
 const root=await mkdtemp(join(tmpdir(),'support-notice-bad-'));
 try{
  const user=await mkUser();
  const badRoot=join(root,'missing');
  const thread=await createSupportThread(user,{subject:'Store down check',
   category:'technical',message:'Can you hear me?'},{db,env:noticeEnv,noticeRoot:badRoot});
  let listing=await listUserSupport(user,{db,env});
  assert.equal(listing.threads[0].messages[0].text,'Can you hear me?');
  await sendSupportMessage(user,thread.id,{message:'Second attempt'},{db,env:noticeEnv,noticeRoot:badRoot});
  listing=await listUserSupport(user,{db,env});
  assert.equal(listing.threads[0].messages.length,2);
  assert.equal(listing.threads[0].messages[1].text,'Second attempt');
 }finally{await rm(root,{recursive:true,force:true});}
});
