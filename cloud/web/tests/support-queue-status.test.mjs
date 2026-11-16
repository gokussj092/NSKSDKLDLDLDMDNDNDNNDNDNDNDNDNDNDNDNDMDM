import test from 'node:test';
import assert from 'node:assert/strict';
import {before,after} from 'node:test';
import {readFile} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {randomUUID,randomBytes} from 'node:crypto';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {countPendingSupport,createSupportThread,sendSupportMessage,
 replyAdminSupport,encryptMessage} from '../lib/commerce/support.mjs';
import {GET as supportQueueGet} from '../app/api/support/queue-status/route.js';

let pg,db,auth,yamadaId;
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:'test-only-secret-not-a-real-credential-0123456789',
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
 yamadaId=randomUUID();
 await db.query(`INSERT INTO spdecode_shop.staff_accounts
   (id,username,display_name,role,password_hash,enabled,must_change_password)
   VALUES($1,'yamada','Yamada','support',$2,true,false)`,
  [yamadaId,'x'.repeat(64)]);
});
after(async()=>{await pg?.close();});

async function newAccount(){
 const id=randomUUID();
 await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
   VALUES($1,$2,$3,true,now(),now())`,[id,'Support User',id+'@example.invalid']);
 return id;
}
async function clearThreads(){
 await db.query(`DELETE FROM spdecode_shop.support_messages`);
 await db.query(`DELETE FROM spdecode_shop.support_threads`);
}
async function makeThread(subject){
 const account=await newAccount();
 const thread=await createSupportThread(account,
  {subject,category:'technical',message:'No me funciona la descarga'},
  {db,env});
 return {account,thread};
}
function yamadaOperator(){return {id:yamadaId,name:'Yamada',role:'support'};}
async function getPending(){
 const res=await supportQueueGet(
  new Request('https://spdecode.xyz/api/support/queue-status'),{db});
 assert.equal(res.status,200);
 const text=await res.text();
 return {text,json:JSON.parse(text)};
}

test('countPendingSupport returns 0 when no Yamada account matches',async()=>{
 await clearThreads();
 assert.equal(await countPendingSupport({db,
  env:{...env,SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'Nadie'}}),0);
});

test('GET returns {pending:0} with no user data when empty',async()=>{
 await clearThreads();
 const {text,json}=await getPending();
 assert.deepEqual(json,{pending:0});
 assert.equal(Object.keys(json).join(),'pending');
 for(const leak of ['threadId','accountId','subject','assigned'])
  assert.equal(text.includes(leak),false,leak);
});

test('counts only Yamada threads whose latest message is from the user',async()=>{
 await clearThreads();
 // t1: assigned to Yamada, user wrote first -> counts.
 const t1=await makeThread('Fallo del decodificador XYZ');
 // t2: assigned to Yamada, Yamada replied last -> does not count.
 const t2=await makeThread('Duda sobre el catalogo ABC');
 await replyAdminSupport(yamadaOperator(),
  {threadId:t2.thread.id,action:'reply',message:'Lo revisamos ahora mismo.'},{db,env});
 // t3: assigned to Yamada, user followed up after creation -> counts.
 const t3=await makeThread('Error al importar DEF');
 await sendSupportMessage(t3.account,t3.thread.id,
  {message:'Sigue sin funcionar despues de reinstalar.'},{db,env});
 // t4: unassigned thread, user wrote -> does not count.
 const t4account=await newAccount();
 const t4id=randomUUID(),t4msg=randomUUID();
 await db.query(`INSERT INTO spdecode_shop.support_threads
   (id,account_id,subject,category,status,assigned_staff_id)
   VALUES($1,$2,'Sin asignar GHI','technical','open',NULL)`,
  [t4id,t4account]);
 await db.query(`INSERT INTO spdecode_shop.support_messages
   (id,thread_id,sender_kind,ciphertext) VALUES($1,$2,'user',$3)`,
  [t4msg,t4id,encryptMessage(t4id,t4msg,'user','Nadie me atiende.',{env})]);
 // t5: assigned to Yamada but closed, last message from the user -> does not count.
 const t5=await makeThread('Hilo cerrado JKL');
 await replyAdminSupport(yamadaOperator(),
  {threadId:t5.thread.id,action:'close'},{db,env});
 assert.equal(await countPendingSupport({db}),2);
 const {text,json}=await getPending();
 assert.deepEqual(json,{pending:2});
 assert.equal(Object.keys(json).join(),'pending');
 for(const leak of [t1.thread.id,t2.thread.id,t3.thread.id,t4id,t5.thread.id,
   t1.account,t2.account,t3.account,t4account,t5.account,
   'Fallo del decodificador XYZ','Duda sobre el catalogo ABC',
   'Error al importar DEF','Sin asignar GHI','Hilo cerrado JKL',
   'threadId','accountId'])
  assert.equal(text.includes(leak),false,leak);
});

test('route is public: no auth/session code, not under /api/v1',async()=>{
 const src=await readFile(new URL('../app/api/support/queue-status/route.js',import.meta.url),'utf8');
 for(const leak of ['requirePanel','requireAccount','verifyBotToken','authenticate','cookie','authorization'])
  assert.equal(src.includes(leak),false,leak);
 assert.equal(existsSync(new URL('../app/api/support/queue-status/route.js',import.meta.url)),true);
 assert.equal(existsSync(new URL('../app/api/v1/support/queue-status/route.js',import.meta.url)),false);
});
