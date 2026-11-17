import {createHmac} from 'node:crypto';
import {database} from './db.mjs';
import {fail,safe,reply,jsonBody} from './config.mjs';
import {requirePanel} from './staff.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';
import {encryptPushToken,decryptPushToken} from './account-notices.mjs';
import {pushAdminNotice,adminPushAccount} from '../notice-push.mjs';
import {transactStoredFeed,readAdministrativeQuarantine,isAdministrativeNotice} from '../notice-store.mjs';

const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(v);
const recipient=v=>v==='owner'||uuid(v);
const labels={support_message:['Nuevo mensaje de soporte','Un usuario escribió en soporte y necesita respuesta.'],
 support_escalation:['Soporte escalado a Ghost Developer','Un hilo de soporte necesita la intervención de Ghost Developer.']};
function tokenEnv(env){
 if(!/^[a-f0-9]{64}$/i.test(env.SPDECODE_SUPPORT_ENCRYPTION_KEY||''))fail('PUSH_NOT_CONFIGURED',503);
 return {...env,SPDECODE_SUPPORT_ENCRYPTION_KEY:createHmac('sha256',Buffer.from(env.SPDECODE_SUPPORT_ENCRYPTION_KEY,'hex'))
  .update('SPDECODE_ADMIN_FCM_KEY_V1').digest('hex')};
}
export function adminRecipient(principal){
 if(principal?.mustChangePassword)fail('FORBIDDEN',403);
 const id=principal?.role==='owner'?'owner':principal?.id;
 if(!recipient(id))fail('UNAUTHORIZED',401);
 return id;
}
export async function recordAdminNotice(db,{id,recipientId,kind,threadId=null,createdAt=null,expiresAt=null}){
 if(!uuid(id)||!recipient(recipientId)||!Object.hasOwn(labels,kind)||threadId!==null&&!uuid(threadId))fail('INVALID_NOTICE_EVENT');
 const out=await db.query(`INSERT INTO spdecode_shop.admin_notices
  (id,recipient_id,kind,thread_id,created_at,expires_at) VALUES($1,$2,$3,$4,COALESCE($5::timestamptz,now()),COALESCE($6::timestamptz,now()+interval '24 hours'))
  ON CONFLICT(recipient_id,id) DO NOTHING RETURNING id`,[id,recipientId,kind,threadId,createdAt,expiresAt]);
 return out.rows[0]?.id??null;
}
export async function registerAdminPush(recipientId,token,{db=database(),env=process.env}={}){
 if(!recipient(recipientId))fail('INVALID_REQUEST');
 const encrypted=encryptPushToken(recipientId,token,tokenEnv(env));
 await db.query(`INSERT INTO spdecode_shop.admin_push_devices(token_digest,recipient_id,token_ciphertext)
  VALUES($1,$2,$3) ON CONFLICT(token_digest) DO UPDATE SET recipient_id=excluded.recipient_id,
  token_ciphertext=excluded.token_ciphertext,seen_at=now()`,[encrypted.digest,recipientId,encrypted.ciphertext]);
 return {registered:true};
}
export async function pushAdminRecipientNotice(recipientId,id,{db=database(),env=process.env,send=pushAdminNotice}={}){
 if(!recipient(recipientId)||!uuid(id))return {queued:0};
 const owned=await db.query('SELECT id FROM spdecode_shop.admin_notices WHERE recipient_id=$1 AND id=$2',[recipientId,id]);
 if(!owned.rowCount)return {queued:0};
 const devices=await db.query(`SELECT token_ciphertext FROM spdecode_shop.admin_push_devices
  WHERE recipient_id=$1 AND seen_at>now()-interval '45 days' ORDER BY seen_at DESC LIMIT 8`,[recipientId]);
 let queued=0;
 await Promise.allSettled(devices.rows.map(async row=>{
  const token=decryptPushToken(recipientId,row.token_ciphertext,tokenEnv(env));
  if(await send(id,{env,targetToken:token,privateKind:'support',priority:'high'})==='push')queued++;
 }));
 return {queued};
}
export async function adminInbox(recipientId,{db=database(),env=process.env,root}={}){
 if(!recipient(recipientId))fail('UNAUTHORIZED',401);
 // Recover old internal disk notices for the owner, with canonical labels.
 // They remain quarantined from all public reads even if this import fails.
 if(recipientId==='owner'){
  try{
   await transactStoredFeed(null,{env,root});
   const legacy=await readAdministrativeQuarantine({env,root});
   for(const n of legacy||[])if(isAdministrativeNotice(n)&&n.expiresAt>Date.now())
    await recordAdminNotice(db,{id:n.id,recipientId,kind:n.title==='Nuevo mensaje de soporte'?'support_message':'support_escalation',
      createdAt:new Date(n.createdAt),expiresAt:new Date(n.expiresAt)});
  }catch{}
 }
 const rows=await db.query(`SELECT id,kind,thread_id,created_at,expires_at,read_at FROM spdecode_shop.admin_notices
  WHERE recipient_id=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 70`,[recipientId]);
 return {audience:'admin',pushConfigured:!!adminPushAccount(env),notices:rows.rows.map(r=>({id:r.id,
  title:labels[r.kind][0],body:labels[r.kind][1],type:'general',importance:r.kind==='support_escalation'?'important':'normal',
  delivery:'poll',createdAt:new Date(r.created_at).getTime(),expiresAt:new Date(r.expires_at).getTime(),readAt:r.read_at}))};
}
export const adminInboxRequest=(request,options={})=>safe(async()=>{
 const principal=await (options.authorize||requirePanel)(request,'support.read');
 const id=adminRecipient(principal);
 if(request.method==='GET')return reply(await adminInbox(id,options));
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 if(!validMutation(request,adminSettings()))fail('CSRF_REJECTED',403);
 const body=await jsonBody(request,1200),keys=Object.keys(body||{}).sort().join(',');
 if(keys==='action,token'&&body.action==='register')return reply(await registerAdminPush(id,body.token,options));
 if(keys==='action,token'&&body.action==='unregister'){
  const {digest}=encryptPushToken(id,body.token,tokenEnv(options.env||process.env));
  await (options.db||database()).query('DELETE FROM spdecode_shop.admin_push_devices WHERE recipient_id=$1 AND token_digest=$2',[id,digest]);
  return reply({removed:true});
 }
 if(keys==='action,id'&&body.action==='read'&&uuid(body.id)){
  const out=await (options.db||database()).query('UPDATE spdecode_shop.admin_notices SET read_at=COALESCE(read_at,now()) WHERE recipient_id=$1 AND id=$2 RETURNING id',[id,body.id]);
  if(!out.rowCount)fail('NOTICE_NOT_FOUND',404);return reply({read:true});
 }
 fail('INVALID_REQUEST');
});
