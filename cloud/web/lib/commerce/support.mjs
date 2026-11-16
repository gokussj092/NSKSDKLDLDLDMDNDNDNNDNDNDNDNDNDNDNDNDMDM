import {randomBytes,randomUUID,createCipheriv,createDecipheriv} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {recordAccountNotice,pushAccountNotice} from './account-notices.mjs';
import {avatarInput} from './profile.mjs';
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
      role:row.agent_role||'support',
      avatar:row.agent_avatar??null
    }}:{})};
}
// Last read position per actor (user account or staff id). Threads with no row
// count every opposite-side message as unread.
async function readTimes(db,readerKind,readerId){
  const rows=(await db.query(`SELECT thread_id,read_at
    FROM spdecode_shop.support_thread_reads
    WHERE reader_kind=$1 AND reader_id=$2`,[readerKind,readerId])).rows;
  return new Map(rows.map(r=>[r.thread_id,new Date(r.read_at).getTime()]));
}
export async function markSupportThreadRead(threadId,reader,{db=database()}={}){
  if(!UUID.test(threadId)||!reader||!['user','staff'].includes(reader.kind)||
     typeof reader.id!=='string'||!reader.id)fail('INVALID_REQUEST');
  const row=(await db.query(`SELECT id,account_id,assigned_staff_id
    FROM spdecode_shop.support_threads WHERE id=$1`,[threadId])).rows[0];
  if(!row)fail('SUPPORT_NOT_FOUND',404);
  if(reader.kind==='user'&&row.account_id!==reader.id)fail('SUPPORT_NOT_FOUND',404);
  if(reader.kind==='staff'&&!reader.canSeeAll&&row.assigned_staff_id!==reader.id)
    fail('SUPPORT_NOT_ASSIGNED',403);
  await db.query(`INSERT INTO spdecode_shop.support_thread_reads
    (thread_id,reader_kind,reader_id,read_at) VALUES($1,$2,$3,now())
    ON CONFLICT(thread_id,reader_kind,reader_id) DO UPDATE SET read_at=now()`,
    [threadId,reader.kind,reader.id]);
  return {read:true};
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
// Anti-spam (D9-D11): one active suspension per account at most; a suspension
// only blocks creating threads and sending messages, never the rest of the
// account. Expired or lifted rows stay for audit and prior counts.
const SUSPENSION_REASON='too_many_tickets';
const SUSPENSION_TICKETS_PER_DAY=4;
const SUSPENSION_DURATION='1 hour';
export async function activeSuspension(db,accountId){
  const row=(await db.query(`SELECT id,reason,suspended_until
    FROM spdecode_shop.support_suspensions
    WHERE account_id=$1 AND lifted_at IS NULL AND suspended_until>now()
    ORDER BY suspended_until DESC LIMIT 1`,[accountId])).rows[0];
  return row||null;
}
const suspensionView=row=>row?{suspendedUntil:new Date(row.suspended_until).toISOString(),
  reason:row.reason}:null;
async function requireNoSuspension(db,accountId){
  const row=await activeSuspension(db,accountId);
  if(row)fail('SUPPORT_SUSPENDED',429,{suspendedUntil:new Date(row.suspended_until).toISOString()});
}
// Auto-assignment (D5): every new thread goes to the staff account named
// SPDECODE_SUPPORT_AUTO_ASSIGN_NAME (default 'Yamada'), case-insensitive,
// when that account exists, is enabled and can do support work. Support role
// wins over admin/moderator. Returns the staff id or null; null is not an
// error (the account is created later by the owner) and leaves the thread
// unassigned so limited staff can still see it in the admin list.
export async function findAutoAssignStaffId(db,env=process.env){
  const name=(env.SPDECODE_SUPPORT_AUTO_ASSIGN_NAME||'Yamada').trim()||'Yamada';
  const row=(await db.query(`SELECT a.id FROM spdecode_shop.staff_accounts a
    LEFT JOIN spdecode_shop.staff_custom_roles c ON c.code=a.role
    WHERE a.enabled=true AND lower(a.display_name)=lower($1)
      AND (a.role IN ('admin','support','moderator') OR
           (c.enabled=true AND c.permissions @> ARRAY['support.write']::text[]))
    ORDER BY CASE WHEN a.role='support' THEN 0 ELSE 1 END, a.created_at ASC
    LIMIT 1`,[name])).rows[0];
  return row?.id||null;
}
// Single open ticket (D4): close every other non-closed thread of the account.
async function closeOtherThreads(client,accountId){
  await client.query(`UPDATE spdecode_shop.support_threads SET status='closed'
    WHERE account_id=$1 AND status<>'closed'`,[accountId]);
}
// Inactivity close (D4): a thread closes after 1 hour without a user reply,
// i.e. only when the last message is from staff. Lazy evaluation: there are
// no background jobs on this server, so callers run it on list.
export async function closeInactiveThreads(db){
  await db.query(`UPDATE spdecode_shop.support_threads t SET status='closed'
    FROM (SELECT DISTINCT ON (thread_id) thread_id,sender_kind
      FROM spdecode_shop.support_messages
      ORDER BY thread_id,created_at DESC,id DESC) last
    WHERE t.id=last.thread_id AND t.status<>'closed'
      AND t.last_message_at<now()-interval '1 hour'
      AND last.sender_kind='admin'`);
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
  await requireNoSuspension(db,accountId);
  await rate(accountId,db);
  return transaction(async client=>{
    const account=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId]);
    if(!account.rowCount)fail('SIGN_IN_REQUIRED',401);
    await closeOtherThreads(client,accountId);
    const active=(await client.query(`SELECT COUNT(*)::integer AS n
      FROM spdecode_shop.support_threads WHERE account_id=$1 AND status<>'closed'`,[accountId])).rows[0]?.n;
    if(active>=10)fail('SUPPORT_THREADS_LIMIT',429);
    const today=(await client.query(`SELECT COUNT(*)::integer AS n
      FROM spdecode_shop.support_threads WHERE account_id=$1
      AND created_at AT TIME ZONE 'UTC'>=date_trunc('day',now() AT TIME ZONE 'UTC')`,[accountId])).rows[0]?.n??0;
    const assignedStaffId=await findAutoAssignStaffId(client,env);
    const id=randomUUID(),msg=randomUUID();
    await client.query(`INSERT INTO spdecode_shop.support_threads(id,account_id,category,subject,assigned_staff_id)
      VALUES($1,$2,$3,$4,$5)`,[id,accountId,category,subject.trim(),assignedStaffId]);
    await client.query(`INSERT INTO spdecode_shop.support_messages(id,thread_id,sender_kind,ciphertext)
      VALUES($1,$2,'user',$3)`,[msg,id,encryptMessage(id,msg,'user',text,{env})]);
    let suspendedUntil=null;
    if(today+1>=SUSPENSION_TICKETS_PER_DAY){
      suspendedUntil=(await client.query(`INSERT INTO spdecode_shop.support_suspensions
        (account_id,reason,suspended_until) VALUES($1,$2,now()+$3::interval)
        RETURNING suspended_until`,[accountId,SUSPENSION_REASON,SUSPENSION_DURATION])).rows[0].suspended_until;
    }
    return {id,created:true,assignedStaffId,
      ...(suspendedUntil?{suspendedUntil:new Date(suspendedUntil).toISOString()}:{})};
  },db);
}
export async function sendSupportMessage(accountId,threadId,input,{db=database(),env=process.env}={}){
  secret(env);
  if(!UUID.test(threadId)||Object.keys(input||{}).some(k=>k!=='message'))fail('INVALID_REQUEST');
  const text=validateText(input?.message);
  await requireNoSuspension(db,accountId);
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
  await closeInactiveThreads(db);
  const threads=(await db.query(`SELECT id,subject,category,status,last_message_at
    FROM spdecode_shop.support_threads WHERE account_id=$1
    ORDER BY last_message_at DESC LIMIT 50`,[accountId])).rows;
  const reads=await readTimes(db,'user',accountId);
  const staffReads=new Map((await db.query(`SELECT r.thread_id,MAX(r.read_at) AS staff_read_at
    FROM spdecode_shop.support_thread_reads r
    JOIN spdecode_shop.support_threads t ON t.id=r.thread_id
    WHERE r.reader_kind='staff' AND t.account_id=$1
    GROUP BY r.thread_id`,[accountId])).rows.map(r=>[r.thread_id,new Date(r.staff_read_at).toISOString()]));
  const suspension=await activeSuspension(db,accountId);
  const messages=await Promise.all(threads.map(async thread=>{
    const rows=(await db.query(`SELECT id,thread_id,sender_kind,ciphertext,created_at,agent_name,agent_role,agent_avatar
      FROM spdecode_shop.support_messages WHERE thread_id=$1
      ORDER BY created_at ASC,id ASC LIMIT 150`,[thread.id])).rows;
    const rendered=rows.map(x=>messageRow(x,env));
    const since=reads.get(thread.id);
    const unread=rendered.filter(m=>m.sender==='admin'&&
      (since===undefined||new Date(m.at).getTime()>since)).length;
    // D7: the client marks the user's messages as "read" up to this point.
    const staffReadAt=staffReads.get(thread.id)??null;
    return {...thread,unread,staffReadAt,messages:rendered};
  }));
  return {threads:messages,unreadTotal:messages.reduce((n,t)=>n+t.unread,0),
    suspension:suspensionView(suspension)};
}
export async function listAdminSupport({db=database(),env=process.env,principal=null}={}){
  secret(env);
  await closeInactiveThreads(db);
  const limited=!!principal&&!principal.capabilities?.includes('support.assign');
  const threads=(await db.query(`SELECT t.id,t.subject,t.category,t.status,t.priority,
    t.assigned_staff_id,t.last_message_at,t.account_id,u.name,p.username,
    COALESCE(p.avatar_data,u.image) AS avatar,
    assigned.display_name AS assigned_name,assigned.username AS assigned_username
    FROM spdecode_shop.support_threads t
    JOIN shop_user u ON u.id=t.account_id
    LEFT JOIN spdecode_shop.profiles p ON p.account_id=t.account_id
    LEFT JOIN spdecode_shop.staff_accounts assigned ON assigned.id=t.assigned_staff_id
    WHERE ($1::boolean=false OR t.assigned_staff_id=$2::uuid OR t.assigned_staff_id IS NULL)
    ORDER BY t.last_message_at DESC LIMIT 100`,
    [limited,limited?principal.id:null])).rows;
  const agents=principal?.capabilities?.includes('support.assign')?(await db.query(`
    SELECT a.id,a.display_name AS name,a.username,a.role FROM spdecode_shop.staff_accounts a
    LEFT JOIN spdecode_shop.staff_custom_roles c ON c.code=a.role
    WHERE a.enabled=true AND a.must_change_password=false AND
      (a.role IN ('admin','support','moderator') OR
       (c.enabled=true AND c.permissions @> ARRAY['support.write']::text[]))
    ORDER BY a.display_name,a.id LIMIT 200`)).rows:[];
  const reads=principal?await readTimes(db,'staff',principal.id):new Map();
  // One query for every active suspension of the listed accounts (no N+1);
  // priorCount counts earlier suspensions of the same account, not the active one.
  const accountIds=[...new Set(threads.map(t=>t.account_id))];
  const suspensions=accountIds.length?(await db.query(`SELECT s.account_id,s.suspended_until,s.reason,
    (SELECT COUNT(*)::integer FROM spdecode_shop.support_suspensions s2
     WHERE s2.account_id=s.account_id AND s2.id<>s.id) AS prior_count
    FROM spdecode_shop.support_suspensions s
    WHERE s.lifted_at IS NULL AND s.suspended_until>now()
    AND s.account_id=ANY($1::text[])`,[accountIds])).rows:[];
  const suspensionByAccount=new Map(suspensions.map(s=>[s.account_id,
    {...suspensionView(s),priorCount:s.prior_count}]));
  const threadsWithMessages=await Promise.all(threads.map(async t=>{
    const rows=(await db.query(`SELECT id,thread_id,sender_kind,ciphertext,created_at,agent_name,agent_role,agent_avatar
      FROM spdecode_shop.support_messages WHERE thread_id=$1
      ORDER BY created_at ASC,id ASC LIMIT 150`,[t.id])).rows;
    const rendered=rows.map(row=>messageRow(row,env));
    const since=reads.get(t.id);
    const unread=rendered.filter(m=>m.sender==='user'&&
      (since===undefined||new Date(m.at).getTime()>since)).length;
    return {...t,unread,suspension:suspensionByAccount.get(t.account_id)??null,messages:rendered};
  }));
  return {agents,threads:threadsWithMessages,
    unreadTotal:threadsWithMessages.reduce((n,t)=>n+t.unread,0)};
}
export async function replyAdminSupport(actor,input,{db=database(),env=process.env}={}){
  secret(env);
  const operator=typeof actor==='string'?{id:actor,name:'SP-DECODE',role:'admin'}:actor;
  const keys=Object.keys(input||{});
  if(!operator||typeof operator.id!=='string'||!operator.id||
     typeof operator.name!=='string'||operator.name.length<2||operator.name.length>80||
     !/^(owner|admin|support|moderator|x_[a-z][a-z0-9_]{1,12})$/.test(operator.role)||
     !UUID.test(input?.threadId)||
    keys.some(k=>!['threadId','action','message','subject'].includes(k))||
    !['reply','close','reopen','rename'].includes(input?.action)||
    (input.action==='rename'&&(typeof input.subject!=='string'||
      input.subject.trim().length<4||input.subject.trim().length>100))||
    (input.action!=='rename'&&keys.includes('subject')))fail('INVALID_REQUEST');
  const text=input.action==='reply'?validateText(input.message):null;
  // D3: the title is set by Yamada; rename changes only the subject, never
  // the status or last_message_at.
  const subject=input.action==='rename'?input.subject.trim():null;
  // Avatar snapshot: same rule as user profile avatars (data-URI JPEG ≤ 85 KB).
  // Undefined keeps the message without avatar; null clears it explicitly.
  const avatar=avatarInput(operator.avatar);
  const result=await transaction(async client=>{
    const thread=(await client.query('SELECT id,status,account_id,assigned_staff_id FROM spdecode_shop.support_threads WHERE id=$1 FOR UPDATE',
      [input.threadId])).rows[0];
    if(!thread)fail('SUPPORT_NOT_FOUND',404);
    if(!['owner','admin','moderator'].includes(operator.role)&&
       !operator.canAssign&&thread.assigned_staff_id!==operator.id)
      fail('SUPPORT_NOT_ASSIGNED',403);
    let accountNoticeId=null;
    if(input.action==='rename'){
      await client.query(`UPDATE spdecode_shop.support_threads SET subject=$2 WHERE id=$1`,
        [thread.id,subject]);
    }
    if(input.action==='reply'){
      if(thread.status==='closed')fail('SUPPORT_THREAD_CLOSED',409);
      const id=randomUUID();
      await client.query(`INSERT INTO spdecode_shop.support_messages
        (id,thread_id,sender_kind,ciphertext,agent_id,agent_name,agent_role,agent_avatar)
        VALUES($1,$2,'admin',$3,$4,$5,$6,$7)`,
        [id,thread.id,encryptMessage(thread.id,id,'admin',text,{env}),
         operator.id,operator.name,operator.role,avatar??null]);
      accountNoticeId=await recordAccountNotice(client,thread.account_id,
        'support:'+id,'support',thread.id);
    }
    const state=input.action==='rename'?thread.status:
      input.action==='reply'?'answered':input.action==='close'?'closed':'open';
    if(input.action!=='rename'){
      await client.query(`UPDATE spdecode_shop.support_threads SET status=$2,
        last_message_at=now() WHERE id=$1`,[thread.id,state]);
    }
    await client.query(`INSERT INTO spdecode_shop.audit(actor_id,action,resource_id)
      VALUES($1,$2,$3)`,[operator.id,'support_'+input.action,thread.id]);
    await client.query(`INSERT INTO spdecode_shop.staff_audit
      (id,actor_id,actor_role,action,target_id,details)
      VALUES($1,$2,$3,$4,$5,$6)`,[
      randomUUID(),operator.id,operator.role,'support_'+input.action,thread.id,
      JSON.stringify(input.action==='rename'?{status:state,subject}:{status:state})]);
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

// Manual lift of an anti-spam suspension (D11 subnote: both Yamada and Pedro).
// support.write covers the support role (Yamada) and the owner. A lifted
// suspension stays in the table with lifted_at set, so it still counts as a
// prior suspension for the panel.
const SUPPORT_WRITE_ROLES=new Set(['owner','admin','support','moderator']);
function canWriteSupport(principal){
  if(!principal||typeof principal.id!=='string'||!principal.id)return false;
  if(Array.isArray(principal.capabilities))
    return principal.capabilities.includes('support.write');
  return SUPPORT_WRITE_ROLES.has(principal.role);
}
export async function liftSupportSuspension(principal,accountId,{db=database()}={}){
  if(!canWriteSupport(principal)||typeof accountId!=='string'||!accountId||
     accountId.length>128)fail('INVALID_REQUEST');
  return transaction(async client=>{
    const row=(await client.query(`UPDATE spdecode_shop.support_suspensions
      SET lifted_at=now(),lifted_by=$2
      WHERE account_id=$1 AND lifted_at IS NULL AND suspended_until>now()
      RETURNING id`,[accountId,principal.id])).rows[0];
    if(!row)return {lifted:false};
    await client.query(`INSERT INTO spdecode_shop.staff_audit
      (id,actor_id,actor_role,action,target_id,details)
      VALUES($1,$2,$3,'support_suspension_lifted',$4,$5)`,[
      randomUUID(),principal.id,principal.role||'support',accountId,
      JSON.stringify({suspensionId:row.id})]);
    return {lifted:true};
  },db);
}
