import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {createStaff,updateStaff,listStaff,loginStaff,panelPrincipal,can,
  changeStaffPassword,recentStaffAudit} from '../lib/commerce/staff.mjs';
import {createSupportThread,assignSupportThread,replyAdminSupport,
  listAdminSupport,listUserSupport} from '../lib/commerce/support.mjs';
import {userDirectory,userDetail} from '../lib/commerce/users-admin.mjs';
let pg,db,auth,redis;
const users=[randomUUID(),randomUUID()],owner={
 id:'f'.repeat(64),name:'SP-DECODE Owner',username:'rootadmin',
 role:'owner',mustChangePassword:false
};
const env={...process.env,NODE_ENV:'test',
 CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 BETTER_AUTH_SECRET:'staff-test-secret-'.repeat(4),
 GOOGLE_CLIENT_ID:'synthetic.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_SUPPORT_ENCRYPTION_KEY:randomBytes(32).toString('hex')};
Object.assign(process.env,env);
const config={enabled:true,username:owner.username,signingKey:'staff-signing-secret-'.repeat(4),
 passwordHash:'invalid-hash',publicOrigin:'https://panel.spdecode.xyz'};
before(async()=>{
 pg=new PGlite();
 const query=async(sql,params=[])=>{
  const r=await pg.query(sql,params);
  return {rows:r.rows,rowCount:r.rows.length||r.affectedRows||0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 await (await getMigrations(auth.options)).runMigrations();
 for(const name of ['002_shop.sql','003_ads_free.sql','004_gifts.sql',
   '005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql']){
  const sql=await readFile(new URL('../sql/'+name,import.meta.url),'utf8');
  await pg.exec(sql);
 }
 for(const [i,id] of users.entries()){
  await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
  VALUES($1,$2,$3,true,now(),now())`,
   [id,'Test Customer '+i,'staff-test-'+i+'@example.invalid']);
 }
 const values=new Map();
 redis={
  eval:async()=>1,
  set:async(k,v)=>{values.set(k,v);return 'OK'},
  get:async k=>values.get(k)||null,
  del:async k=>{values.delete(k);return 1}
 };
});
after(async()=>{await pg?.close();});
test('owner creates scoped staff with non-recoverable password hash',async()=>{
 const created=await createStaff(owner,{username:'agent.qa',name:'Agent QA',role:'support'},{db});
 assert.equal(created.staff.role,'support');
 assert.ok(created.temporaryPassword.length>=24);
 const record=(await db.query('SELECT * FROM spdecode_shop.staff_accounts WHERE id=$1',[created.staff.id])).rows[0];
 assert.notEqual(record.password_hash,created.temporaryPassword);
 assert.equal(record.must_change_password,true);
 const listing=await listStaff({db});
 assert.ok(!JSON.stringify(listing).includes(created.temporaryPassword));
 assert.ok(!JSON.stringify(listing).includes(record.password_hash));
 assert.equal(listing.staff[0].username,'agent.qa');
 await assert.rejects(createStaff({id:users[0],role:'support'},{
   username:'agent.two',name:'Agent 2',role:'admin'},{db}),/FORBIDDEN/);
 await assert.rejects(createStaff(owner,{username:'agent.qa',name:'Dup',role:'admin'},{db}),/STAFF_USERNAME_TAKEN/);
 globalThis.staffTestCredentials=created;
});
test('login and first-password-change gate are mandatory; roles never grant VPS owner powers',async()=>{
 const created=globalThis.staffTestCredentials;
 const result=await loginStaff(redis,created.staff.username,created.temporaryPassword,{db,config});
 assert.equal(result.mustChangePassword,true);
 const req=new Request('https://panel.spdecode.xyz/api/admin/access',{
  headers:{cookie:'spdecode_staff_session='+result.token}});
 const actor=await panelPrincipal(req,{db,redis,config});
 assert.equal(actor.id,created.staff.id);
 assert.equal(actor.role,'support');
 assert.equal(can(actor,'support.read'),false);
 assert.equal(can(actor,'staff.write'),false);
 await changeStaffPassword(actor,created.temporaryPassword,'UserNewPassword!2026Secure',
  {db});
 assert.equal(await panelPrincipal(req,{db,redis,config}),null);
 await assert.rejects(loginStaff(redis,created.staff.username,
  created.temporaryPassword,{db,config}),/INVALID_CREDENTIALS/);
 const next=await loginStaff(redis,created.staff.username,'UserNewPassword!2026Secure',{db,config});
 assert.equal(next.mustChangePassword,false);
 const request=new Request('https://panel.spdecode.xyz/api/admin/access',{
  headers:{cookie:'spdecode_staff_session='+next.token}});
 const fresh=await panelPrincipal(request,{db,redis,config});
 assert.equal(can(fresh,'support.read'),true);
 assert.equal(can(fresh,'users.read'),false);
 assert.equal(can(fresh,'staff.write'),false);
 globalThis.staffTestActor=fresh;
});
test('assignment controls which support agent can see or answer customer',async()=>{
 const created=globalThis.staffTestCredentials,actor=globalThis.staffTestActor;
 const thread=await createSupportThread(users[0],{subject:'App login issue',
  category:'account',message:'I cannot open my account'},{db,env});
 const ownerResult=await assignSupportThread(owner,{
  threadId:thread.id,action:'assign',assignedId:created.staff.id,priority:'high'},{db});
 assert.equal(ownerResult.priority,'high');
 const listed=await listAdminSupport({db,env,principal:actor});
 assert.equal(listed.threads.length,1);
 assert.equal(listed.threads[0].assigned_name,'Agent QA');
 await replyAdminSupport({id:actor.id,name:actor.name,role:'support'},
  {threadId:thread.id,action:'reply',message:'We are checking your login.'},{db,env});
 const client=await listUserSupport(users[0],{db,env});
 assert.equal(client.threads[0].messages.at(-1).agent.name,'Agent QA');
 assert.equal(client.threads[0].messages.at(-1).agent.role,'support');
 await assert.rejects(replyAdminSupport({id:randomUUID(),name:'Other',role:'support'},
  {threadId:thread.id,action:'reply',message:'Not allowed'},{db,env}),/SUPPORT_NOT_ASSIGNED/);
 await assert.rejects(assignSupportThread(actor,{threadId:thread.id,action:'assign',
  assignedId:null,priority:'normal'},{db}),/INVALID_REQUEST/);
});
test('owner can edit staff name username role, revoke sessions and reset password',async()=>{
 const initial=globalThis.staffTestCredentials;
 const saved=await updateStaff(owner,{id:initial.staff.id,username:'agent.renamed',
   name:'Customer Care',role:'moderator'},{db});
 assert.equal(saved.staff.name,'Customer Care');
 assert.equal(saved.staff.role,'moderator');
 const reset=await updateStaff(owner,{id:initial.staff.id,resetPassword:true},{db});
 assert.ok(reset.temporaryPassword?.length>=24);
 assert.ok(!JSON.stringify(await listStaff({db})).includes(reset.temporaryPassword));
 const audit=await recentStaffAudit({db});
 assert.ok(audit.events.some(x=>x.action==='staff_updated'));
});
test('registered customers directory is scoped, paginated and redacts secrets',async()=>{
 const list=await userDirectory({db,page:0});
 assert.ok(list.count>=2);
 assert.equal(list.pageSize,30);
 assert.ok(list.users.some(x=>x.id===users[0]));
 const details=await userDetail(owner,users[0],{db});
 assert.equal(details.user.id,users[0]);
 assert.ok(Array.isArray(details.orders));
 const serialized=JSON.stringify(details);
 assert.ok(!serialized.includes('password_hash'));
 assert.ok(!serialized.includes('accessToken'));
 assert.ok(!serialized.includes('refreshToken'));
 const audit=await recentStaffAudit({db});
 assert.ok(audit.events.some(x=>x.action==='customer_viewed'));
 await assert.rejects(userDirectory({db,page:1001}),/INVALID_REQUEST/);
});
