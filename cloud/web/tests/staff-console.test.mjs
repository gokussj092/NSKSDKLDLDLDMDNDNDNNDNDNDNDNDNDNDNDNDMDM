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
  listAdminSupport,listUserSupport,liftSupportSuspension,
  findAutoAssignStaffId} from '../lib/commerce/support.mjs';
import {userDirectory,userDetail} from '../lib/commerce/users-admin.mjs';
import {customRoles,writeCustomRole,roleCapabilities} from '../lib/commerce/staff-roles.mjs';
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
   '005_account_support_apk.sql','006_support_agent_identity.sql','007_staff_permissions.sql','008_account_notifications.sql','009_staff_custom_roles.sql','010_support_reads_avatar.sql','011_support_autoassign_reads_antispam.sql']){
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
 assert.equal(result.expiresIn,90*24*3600);
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
 assert.deepEqual(listed.agents,[]);
 const assignable=await listAdminSupport({db,env,principal:{...owner,capabilities:['support.assign']}});
 assert.equal(assignable.agents[0].id,actor.id);
 assert.ok(!JSON.stringify(assignable.agents).includes('password'));
 assert.ok(!JSON.stringify(assignable.agents).includes('email'));
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
test('owner can set staff avatar (data-URI JPEG) and clear it; invalid avatars rejected',async()=>{
 const initial=globalThis.staffTestCredentials;
 const bytes=Buffer.alloc(100);bytes[0]=0xff;bytes[1]=0xd8;bytes[98]=0xff;bytes[99]=0xd9;
 const avatar='data:image/jpeg;base64,'+bytes.toString('base64');
 const saved=await updateStaff(owner,{id:initial.staff.id,avatar},{db});
 assert.equal(saved.staff.avatar,avatar);
 const listed=await listStaff({db});
 assert.equal(listed.staff.find(s=>s.id===initial.staff.id).avatar,avatar);
 await assert.rejects(updateStaff(owner,{id:initial.staff.id,avatar:'data:image/png;base64,AAAA'},{db}),/INVALID_AVATAR/);
 await assert.rejects(updateStaff(owner,{id:initial.staff.id,avatar:'data:image/jpeg;base64,AAAA'},{db}),/INVALID_AVATAR/);
 const cleared=await updateStaff(owner,{id:initial.staff.id,avatar:null},{db});
 assert.equal(cleared.staff.avatar,null);
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

test('assigned staff can rename a thread title without touching status or time',async()=>{
 // Fresh support agent; manual assignment requires the first-password-change
 // gate to be cleared (assignSupportThread checks must_change_password=false).
 const agent=await createStaff(owner,{username:'rename.qa',name:'Rename QA',role:'support'},{db});
 await db.query(`UPDATE spdecode_shop.staff_accounts SET must_change_password=false WHERE id=$1`,[agent.staff.id]);
 const actor={id:agent.staff.id,name:'Rename QA',role:'support'};
 const thread=await createSupportThread(users[0],{subject:'Provisional title',
  category:'technical',message:'The app crashes on open'},{db,env});
 assert.equal(thread.assignedStaffId,null);
 await assignSupportThread(owner,{threadId:thread.id,action:'assign',
  assignedId:actor.id,priority:'normal'},{db});
 const before=(await db.query(`SELECT status,last_message_at FROM spdecode_shop.support_threads WHERE id=$1`,[thread.id])).rows[0];
 const renamed=await replyAdminSupport({id:actor.id,name:actor.name,role:'support'},
  {threadId:thread.id,action:'rename',subject:'Crash on open'},{db,env});
 assert.equal(renamed.saved,true);
 assert.equal(renamed.status,before.status);
 const after=(await db.query(`SELECT subject,status,last_message_at FROM spdecode_shop.support_threads WHERE id=$1`,[thread.id])).rows[0];
 assert.equal(after.subject,'Crash on open');
 assert.equal(after.status,before.status);
 assert.equal(new Date(after.last_message_at).getTime(),new Date(before.last_message_at).getTime());
 const client=await listUserSupport(users[0],{db,env});
 assert.equal(client.threads.find(t=>t.id===thread.id).subject,'Crash on open');
 const audit=await recentStaffAudit({db});
 assert.ok(audit.events.some(x=>x.action==='support_rename'&&x.target_id===thread.id));
 // Rename validation: too short, and subject on any other action, are refused.
 await assert.rejects(replyAdminSupport({id:actor.id,name:actor.name,role:'support'},
  {threadId:thread.id,action:'rename',subject:'No'},{db,env}),/INVALID_REQUEST/);
 await assert.rejects(replyAdminSupport({id:actor.id,name:actor.name,role:'support'},
  {threadId:thread.id,action:'close',subject:'Crash on open'},{db,env}),/INVALID_REQUEST/);
 // Unassigned staff still cannot rename someone else's thread.
 await assert.rejects(replyAdminSupport({id:randomUUID(),name:'Other',role:'support'},
  {threadId:thread.id,action:'rename',subject:'Other title'},{db,env}),/SUPPORT_NOT_ASSIGNED/);
});
test('support role can lift a suspension; new threads auto-assign to Yamada',async()=>{
 const actor=globalThis.staffTestActor;
 // No Yamada account exists yet: new threads stay unassigned.
 const plain=await createSupportThread(users[1],{subject:'Plain thread',
  category:'technical',message:'First'},{db,env});
 assert.equal(plain.assignedStaffId,null);
 // Limited staff sees unassigned threads too (safety net until auto-assign exists).
 const unassigned=await listAdminSupport({db,env,principal:actor});
 assert.ok(unassigned.threads.some(t=>t.id===plain.id));
 // 4 threads in one day suspend the account; the support role lifts it.
 const mk=subject=>createSupportThread(users[1],{subject,category:'technical',
  message:'Help with '+subject},{db,env});
 await mk('Second thread');
 await mk('Third thread');
 const fourth=await mk('Fourth thread');
 assert.ok(fourth.suspendedUntil);
 const support={id:actor.id,role:'support',capabilities:['support.read','support.write']};
 assert.deepEqual(await liftSupportSuspension(support,users[1],{db}),{lifted:true});
 assert.equal((await listUserSupport(users[1],{db,env})).suspension,null);
});
test('auto-assignment picks the Yamada account, preferring the support role',async()=>{
 // An admin named Yamada exists, but the support-role Yamada wins.
 const adminYamada=await createStaff(owner,{username:'yamada.admin',name:'Yamada',role:'admin'},{db});
 const supportYamada=await createStaff(owner,{username:'yamada.qa',name:'Yamada',role:'support'},{db});
 assert.equal(await findAutoAssignStaffId(db,env),supportYamada.staff.id);
 // Name match is case-insensitive and honours the env override.
 assert.equal(await findAutoAssignStaffId(db,{...env,
  SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'YAMADA'}),supportYamada.staff.id);
 assert.equal(await findAutoAssignStaffId(db,{...env,
  SPDECODE_SUPPORT_AUTO_ASSIGN_NAME:'Nobody'}),null);
 const thread=await createSupportThread(users[0],{subject:'Auto assigned',
  category:'apk',message:'Please help'},{db,env});
 assert.equal(thread.assignedStaffId,supportYamada.staff.id);
 const row=(await db.query('SELECT assigned_staff_id FROM spdecode_shop.support_threads WHERE id=$1',[thread.id])).rows[0];
 assert.equal(row.assigned_staff_id,supportYamada.staff.id);
 const yamadaPrincipal={id:supportYamada.staff.id,
  capabilities:['support.read','support.write']};
 const listed=await listAdminSupport({db,env,principal:yamadaPrincipal});
 assert.ok(listed.threads.some(t=>t.id===thread.id));
});

test('owner creates least-privilege custom role with no escalation to staff administration',async()=>{
 const custom={action:'create',code:'x_careqa',name:'Atención QA',
   permissions:['support.read','support.write'],enabled:true};
 const made=await writeCustomRole(owner,custom,{db});
 assert.equal(made.role.code,'x_careqa');
 assert.deepEqual(await roleCapabilities('x_careqa',db),['support.read','support.write']);
 await assert.rejects(writeCustomRole(owner,{...custom,code:'x_adminqa',
   permissions:['staff.write']},{db}),/INVALID_ROLE/);
 await assert.rejects(writeCustomRole({role:'admin'},custom,{db}),/FORBIDDEN/);
 await assert.rejects(writeCustomRole(owner,{...custom,code:'x_badperm',
   permissions:['support.write']},{db}),/ROLE_REQUIRES_SUPPORT_READ/);
 const person=await createStaff(owner,{username:'custom.qa',name:'Custom Support QA',
   role:'x_careqa'},{db});
 const login=await loginStaff(redis,person.staff.username,person.temporaryPassword,{db,config});
 let req=new Request('https://panel.spdecode.xyz/api/admin/access',{headers:{
  cookie:'spdecode_staff_session='+login.token}});
 let principal=await panelPrincipal(req,{db,redis,config});
 assert.equal(principal.mustChangePassword,true);
 assert.equal(can(principal,'support.read'),false);
 await changeStaffPassword(principal,person.temporaryPassword,'ChangedCustomPass#2026',{db});
 const active=await loginStaff(redis,'custom.qa','ChangedCustomPass#2026',{db,config});
 req=new Request('https://panel.spdecode.xyz/api/admin/access',{
  headers:{cookie:'spdecode_staff_session='+active.token}});
 principal=await panelPrincipal(req,{db,redis,config});
 assert.ok(can(principal,'support.read'));
 assert.ok(can(principal,'support.write'));
 assert.equal(can(principal,'support.assign'),false);
 assert.equal(can(principal,'staff.write'),false);
 assert.equal(can(principal,'billing.read'),false);
 const edited=await writeCustomRole(owner,{action:'update',code:'x_careqa',
   name:'Atención QA',permissions:['users.read'],enabled:true},{db});
 assert.equal(edited.role.permissions.length,1);
 assert.equal(await panelPrincipal(req,{db,redis,config}),null);
 const changed=await loginStaff(redis,'custom.qa','ChangedCustomPass#2026',{db,config});
 const req2=new Request('https://panel.spdecode.xyz/api/admin/access',
   {headers:{cookie:'spdecode_staff_session='+changed.token}});
 const refreshed=await panelPrincipal(req2,{db,redis,config});
 assert.equal(can(refreshed,'users.read'),true);
 assert.equal(can(refreshed,'support.read'),false);
 await writeCustomRole(owner,{action:'update',code:'x_careqa',name:'Atención QA',
   permissions:['users.read'],enabled:false},{db});
 assert.equal(await panelPrincipal(req2,{db,redis,config}),null);
 assert.equal(await roleCapabilities('x_careqa',db),null);
});
