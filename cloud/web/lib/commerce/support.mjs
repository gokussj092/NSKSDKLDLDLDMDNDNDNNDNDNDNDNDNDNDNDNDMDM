import {randomBytes,randomUUID,createCipheriv,createDecipheriv} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {recordAccountNotice,pushAccountNotice} from './account-notices.mjs';
import {fail} from './config.mjs';

const UUID=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const CATEGORIES=new Set(['technical','apk','payments','account','other']);
function secret(env=process.env){
  const raw=env.SPDECODE_SUPPORT_ENCRYPTION_KEY||'';
  if(!/^[a-f0-9]{64}$/i.test(raw))fail('SUPPORT_NOT_CONFIGURED',503);
  return Buffer.from(raw,'hex');
}
export function encryptMessage(thread,id,kind,value,{env=process.env}={}){
  if(typeof value!=='string'||!value.trim()||Buffer.byteLength(value,'utf8')>4096)
    fail('INVALID_MESSAGE',400);
  const nonce=randomBytes(12),c=createCipheriv('aes-256-gcm',secret(env),nonce);
  c.setAAD(Buffer.from(thread+'|'+id+'|'+kind));
  const ct=Buffer.concat([c.update(value.trim(),'utf8'),c.final()]);
  return 'v1.'+[nonce,c.getAuthTag(),ct].map(v=>v.toString('base64url')).join('.');
}
export function decryptMessage(row,{env=process.env}={}){
  const [version,n,t,c]=row.ciphertext.split('.');
  if(version!=='v1')fail('SUPPORT_MESSAGE_UNAVAILABLE',503);
  try{
    const d=createDecipheriv('aes-256-gcm',secret(env),Buffer.from(n,'base64url'));
    d.setAAD(Buffer.from(row.thread_id+'|'+row.id+'|'+row.sender_kind));
    d.setAuthTag(Buffer.from(t,'base64url'));
    return Buffer.concat([d.update(Buffer.from(c,'base64url')),d.final()]).toString('utf8');
  }catch{fail('SUPPORT_MESSAGE_UNAVAILABLE',503);}
}
function messageRow(row,env){
  return {id:row.id,sender:row.sender_kind,text:decryptMessage(row,{env}),at:row.created_at,
    ...(row.sender_kind==='admin'?{agent:{
      name:row.agent_name||'SP-DECODE',
      role:row.agent_role||'support'
    }}:{})};
}
async function rate(accountId,db){
  const n=(await db.query(`INSERT INTO spdecode_shop.support_limits(account_id,messages)
    VALUES($1,1) ON CONFLICT(account_id) DO UPDATE SET
      messages=CASE WHEN spdecode_shop.support_limits.window_start<now()-interval '15 minutes'
        THEN 1 ELSE spdecode_shop.support_limits.messages+1 END,
      window_start=CASE WHEN spdecode_shop.support_limits.window_start<now()-interval '15 minutes'
        THEN now() ELSE spdecode_shop.support_limits.window_start END
    RETURNING messages`,[accountId])).rows[0]?.messages;
  if(!Number.isInteger(n)||n>20)fail('SUPPORT_RATE_LIMITED',429);
}
function validateText(text,max=4096){
  if(typeof text!=='string'||!text.trim()||Buffer.byteLength(text,'utf8')>max||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text))fail('INVALID_MESSAGE');
  return text.trim();
}
export async function createSupportThread(accountId,input,{db=database(),env=process.env}={}){
  secret(env);
  const category=input?.category,subject=input?.subject;
  if(!CATEGORIES.has(category)||typeof subject!=='string'||subject.trim().length<4||
      subject.trim().length>100||!input||
      Object.keys(input).some(k=>!['category','subject','message'].includes(k)))fail('INVALID_REQUEST');
  const text=validateText(input.message);
  await rate(accountId,db);
  return transaction(async client=>{
    const account=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId]);
    if(!account.rowCount)fail('SIGN_IN_REQUIRED',401);
    const active=(await client.query(`SELECT COUNT(*)::integer AS n
      FROM spdecode_shop.support_threads WHERE account_id=$1 AND status<>'closed'`,[accountId])).rows[0]?.n;
    if(active>=10)fail('SUPPORT_THREADS_LIMIT',429);
    const id=randomUUID(),msg=randomUUID();
    await client.query(`INSERT INTO spdecode_shop.support_threads(id,account_id,category,subject)
      VALUES($1,$2,$3,$4)`,[id,accountId,category,subject.trim()]);
    await client.query(`INSERT INTO spdecode_shop.support_messages(id,thread_id,sender_kind,ciphertext)
      VALUES($1,$2,'user',$3)`,[msg,id,encryptMessage(id,msg,'user',text,{env})]);
    return {id,created:true};
  },db);
}
export async function sendSupportMessage(accountId,threadId,input,{db=database(),env=process.env}={}){
  secret(env);
  if(!UUID.test(threadId)||Object.keys(input||{}).some(k=>k!=='message'))fail('INVALID_REQUEST');
  const text=validateText(input?.message);
  await rate(accountId,db);
  return transaction(async client=>{
    const row=(await client.query(`SELECT id,status FROM spdecode_shop.support_threads
      WHERE id=$1 AND account_id=$2 FOR UPDATE`,[threadId,accountId])).rows[0];
    if(!row)fail('SUPPORT_NOT_FOUND',404);
    if(row.status==='closed')fail('SUPPORT_THREAD_CLOSED',409);
    const id=randomUUID();
    await client.query(`INSERT INTO spdecode_shop.support_messages(id,thread_id,sender_kind,ciphertext)
      VALUES($1,$2,'user',$3)`,[id,threadId,encryptMessage(threadId,id,'user',text,{env})]);
    await client.query(`UPDATE spdecode_shop.support_threads SET status='open',
      last_message_at=now() WHERE id=$1`,[threadId]);
    return {sent:true,id};
  },db);
}
export async function listUserSupport(accountId,{db=database(),env=process.env}={}){
  secret(env);
  const threads=(await db.query(`SELECT id,subject,category,status,last_message_at
    FROM spdecode_shop.support_threads WHERE account_id=$1
    ORDER BY last_message_at DESC LIMIT 50`,[accountId])).rows;
  const messages=await Promise.all(threads.map(async thread=>{
    const rows=(await db.query(`SELECT id,thread_id,sender_kind,ciphertext,created_at,agent_name,agent_role
      FROM spdecode_shop.support_messages WHERE thread_id=$1
      ORDER BY created_at ASC,id ASC LIMIT 150`,[thread.id])).rows;
    return {...thread,messages:rows.map(x=>messageRow(x,env))};
  }));
  return {threads:messages};
}
export async function listAdminSupport({db=database(),env=process.env,principal=null}={}){
  secret(env);
  const limited=!!principal&&!principal.capabilities?.includes('support.assign');
  const threads=(await db.query(`SELECT t.id,t.subject,t.category,t.status,t.priority,
    t.assigned_staff_id,t.last_message_at,t.account_id,u.name,p.username,
    COALESCE(p.avatar_data,u.image) AS avatar,
    assigned.display_name AS assigned_name,assigned.username AS assigned_username
    FROM spdecode_shop.support_threads t
    JOIN shop_user u ON u.id=t.account_id
    LEFT JOIN spdecode_shop.profiles p ON p.account_id=t.account_id
    LEFT JOIN spdecode_shop.staff_accounts assigned ON assigned.id=t.assigned_staff_id
    WHERE ($1::boolean=false OR t.assigned_staff_id=$2::uuid)
    ORDER BY t.last_message_at DESC LIMIT 100`,
    [limited,limited?principal.id:null])).rows;
  return {threads:await Promise.all(threads.map(async t=>{
    const rows=(await db.query(`SELECT id,thread_id,sender_kind,ciphertext,created_at,agent_name,agent_role
      FROM spdecode_shop.support_messages WHERE thread_id=$1
      ORDER BY created_at ASC,id ASC LIMIT 150`,[t.id])).rows;
    return {...t,messages:rows.map(row=>messageRow(row,env))};
  }))};
}
export async function replyAdminSupport(actor,input,{db=database(),env=process.env}={}){
  secret(env);
  const operator=typeof actor==='string'?{id:actor,name:'SP-DECODE',role:'admin'}:actor;
  if(!operator||typeof operator.id!=='string'||!operator.id||
     typeof operator.name!=='string'||operator.name.length<2||operator.name.length>80||
     !/^(owner|admin|support|moderator|x_[a-z][a-z0-9_]{1,12})$/.test(operator.role)||
     !UUID.test(input?.threadId)||
    Object.keys(input||{}).some(k=>!['threadId','action','message'].includes(k))||
    !['reply','close','reopen'].includes(input?.action))fail('INVALID_REQUEST');
  const text=input.action==='reply'?validateText(input.message):null;
  const result=await transaction(async client=>{
    const thread=(await client.query('SELECT id,status,account_id,assigned_staff_id FROM spdecode_shop.support_threads WHERE id=$1 FOR UPDATE',
      [input.threadId])).rows[0];
    if(!thread)fail('SUPPORT_NOT_FOUND',404);
    if(!['owner','admin','moderator'].includes(operator.role)&&
       !operator.canAssign&&thread.assigned_staff_id!==operator.id)
      fail('SUPPORT_NOT_ASSIGNED',403);
    let accountNoticeId=null;
    if(input.action==='reply'){
      if(thread.status==='closed')fail('SUPPORT_THREAD_CLOSED',409);
      const id=randomUUID();
      await client.query(`INSERT INTO spdecode_shop.support_messages
        (id,thread_id,sender_kind,ciphertext,agent_id,agent_name,agent_role)
        VALUES($1,$2,'admin',$3,$4,$5,$6)`,
        [id,thread.id,encryptMessage(thread.id,id,'admin',text,{env}),
         operator.id,operator.name,operator.role]);
      accountNoticeId=await recordAccountNotice(client,thread.account_id,
        'support:'+id,'support',thread.id);
    }
    const state=input.action==='reply'?'answered':input.action==='close'?'closed':'open';
    await client.query(`UPDATE spdecode_shop.support_threads SET status=$2,
      last_message_at=now() WHERE id=$1`,[thread.id,state]);
    await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
      VALUES($1,$2,$3)`,[operator.id,'support_'+input.action,thread.id]);
    await client.query(`INSERT INTO spdecode_shop.staff_audit
      (id,actor_id,actor_role,action,target_id,details)
      VALUES($1,$2,$3,$4,$5,$6)`,[
      randomUUID(),operator.id,operator.role,'support_'+input.action,thread.id,
      JSON.stringify({status:state})]);
    return {saved:true,status:state,accountId:thread.account_id,accountNoticeId};
  },db);
  if(result.accountNoticeId)
    await pushAccountNotice(result.accountId,result.accountNoticeId,'support',{db,env}).catch(()=>{});
  return {saved:result.saved,status:result.status};
}

export async function assignSupportThread(principal,input,{db=database()}={}){
  if(!(['owner','admin','moderator'].includes(principal?.role)||
      principal?.capabilities?.includes('support.assign'))||
     !UUID.test(input?.threadId)||
     Object.keys(input||{}).some(k=>!['threadId','action','assignedId','priority'].includes(k))||
     input.action!=='assign'||(input.assignedId!==null&&!UUID.test(input.assignedId))||
     (input.priority!==undefined&&!['low','normal','high'].includes(input.priority)))
    fail('INVALID_REQUEST',400);
  return transaction(async client=>{
    const thread=(await client.query('SELECT * FROM spdecode_shop.support_threads WHERE id=$1 FOR UPDATE',[input.threadId])).rows[0];
    if(!thread)fail('SUPPORT_NOT_FOUND',404);
    if(input.assignedId){
      const agent=(await client.query(`SELECT a.id FROM spdecode_shop.staff_accounts a
        LEFT JOIN spdecode_shop.staff_custom_roles c ON c.code=a.role
        WHERE a.id=$1 AND a.enabled=true AND a.must_change_password=false
          AND (a.role IN ('admin','support','moderator') OR
               (c.enabled=true AND c.permissions @> ARRAY['support.write']::text[]))`,
        [input.assignedId])).rows[0];
      if(!agent)fail('AGENT_NOT_AVAILABLE',409);
    }
    await client.query(`UPDATE spdecode_shop.support_threads
       SET assigned_staff_id=$2,priority=$3,updated_by=$4
       WHERE id=$1`,[thread.id,input.assignedId,input.priority??thread.priority,principal.id]);
    await client.query(`INSERT INTO spdecode_shop.staff_audit
     (id,actor_id,actor_role,action,target_id,details)
     VALUES($1,$2,$3,'support_assigned',$4,$5)`,[
       randomUUID(),principal.id,principal.role,thread.id,
       JSON.stringify({assignedStaffId:input.assignedId,priority:input.priority??thread.priority})]);
    return {saved:true,assignedId:input.assignedId,priority:input.priority??thread.priority};
  },db);
}
