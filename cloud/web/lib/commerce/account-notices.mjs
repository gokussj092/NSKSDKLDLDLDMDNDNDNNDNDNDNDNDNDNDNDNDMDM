import {createCipheriv,createDecipheriv,createHmac,randomBytes,randomUUID} from 'node:crypto';
import {database} from './db.mjs';
import {fail,reply,safe,requireOrigin,jsonBody} from './config.mjs';
import {requireAccount} from './auth.mjs';
import {pushNotice} from '../notice-push.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FCM=/^[A-Za-z0-9:_-]{32,512}$/;
const KINDS=new Set(['support','purchase','security','service']);
function pushKey(env=process.env) {
 const source=env.SPDECODE_SUPPORT_ENCRYPTION_KEY;
 if(!/^[0-9a-fA-F]{64}$/.test(source||''))fail('PUSH_NOT_CONFIGURED',503);
 return createHmac('sha256',Buffer.from(source,'hex')).update('SPDECODE_ACCOUNT_FCM_KEY_V1').digest();
}
export function encryptPushToken(accountId,token,env=process.env){
 if(typeof accountId!=='string'||!accountId||!FCM.test(token||''))fail('INVALID_PUSH_TOKEN');
 const key=pushKey(env),iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
 cipher.setAAD(Buffer.from('spdecode:fcm:account:v1:'+accountId));
 const ciphertext=Buffer.concat([cipher.update(token,'utf8'),cipher.final()]);
 const digest=createHmac('sha256',key).update(token).digest('hex');
 return {digest,ciphertext:'v1.'+Buffer.concat([iv,cipher.getAuthTag(),ciphertext]).toString('base64url')};
}
export function decryptPushToken(accountId,ciphertext,env=process.env){
 try{
  if(typeof ciphertext!=='string'||!ciphertext.startsWith('v1.'))throw Error();
  const bytes=Buffer.from(ciphertext.slice(3),'base64url');
  if(bytes.length<29||bytes.length>1024)throw Error();
  const decipher=createDecipheriv('aes-256-gcm',pushKey(env),bytes.subarray(0,12));
  decipher.setAAD(Buffer.from('spdecode:fcm:account:v1:'+accountId));
  decipher.setAuthTag(bytes.subarray(12,28));
  const token=Buffer.concat([decipher.update(bytes.subarray(28)),decipher.final()]).toString('utf8');
  if(!FCM.test(token))throw Error();
  return token;
 }catch{fail('PUSH_TOKEN_UNAVAILABLE',503);}
}
export async function registerPush(accountId,token,{db=database(),env=process.env}={}){
 const encrypted=encryptPushToken(accountId,token,env);
 const owner=(await db.query('SELECT id FROM shop_user WHERE id=$1',[accountId]));
 if(!owner.rowCount)fail('SIGN_IN_REQUIRED',401);
 await db.query(`INSERT INTO spdecode_shop.account_push_devices(token_digest,account_id,token_ciphertext)
  VALUES($1,$2,$3) ON CONFLICT(token_digest) DO UPDATE SET
   account_id=excluded.account_id,token_ciphertext=excluded.token_ciphertext,seen_at=now()`,
  [encrypted.digest,accountId,encrypted.ciphertext]);
 return {registered:true};
}
export async function unregisterPush(accountId,token,{db=database(),env=process.env}={}){
 const {digest}=encryptPushToken(accountId,token,env);
 await db.query('DELETE FROM spdecode_shop.account_push_devices WHERE account_id=$1 AND token_digest=$2',
  [accountId,digest]);
 return {removed:true};
}
const labels={
 support:['Soporte técnico','Tienes una nueva respuesta de soporte.'],
 purchase:['Compras','El estado de tu pedido se ha actualizado.'],
 security:['Seguridad','Hay una actualización de seguridad en tu cuenta.'],
 service:['SP-DECODE','Hay una actualización de los servicios.']
};
/** Execute inside the same transaction as the triggering event. */
export async function recordAccountNotice(client,accountId,eventKey,kind,resourceId=null){
 if(!KINDS.has(kind)||typeof eventKey!=='string'||eventKey.length>160||
    !/^[a-z0-9:_-]+$/.test(eventKey)||resourceId!==null&&
    (typeof resourceId!=='string'||resourceId.length>90))fail('INVALID_NOTICE_EVENT');
 const id=randomUUID(),[title,body]=labels[kind];
 const out=await client.query(`INSERT INTO spdecode_shop.account_notices
   (id,account_id,event_key,kind,resource_id,title,body)
   VALUES($1,$2,$3,$4,$5,$6,$7)
   ON CONFLICT(account_id,event_key) DO NOTHING RETURNING id`,
   [id,accountId,eventKey,kind,resourceId,title,body]);
 return out.rowCount?out.rows[0].id:null;
}
/** Push contains only an opaque UUID and generic notification text. */
export async function pushAccountNotice(accountId,id,kind,{db=database(),env=process.env,send=pushNotice}={}){
 if(!id||!UUID.test(id)||!KINDS.has(kind))return {queued:0};
 const result=await db.query(`SELECT token_ciphertext FROM spdecode_shop.account_push_devices
  WHERE account_id=$1 AND seen_at>now()-interval '45 days'
  ORDER BY seen_at DESC LIMIT 8`,[accountId]);
 let sent=0;
 await Promise.allSettled(result.rows.map(async row=>{
   const token=decryptPushToken(accountId,row.token_ciphertext,env);
   if(await send(id,{targetToken:token,privateKind:kind,priority:'high',env})==='push')sent++;
 }));
 return {queued:sent};
}
export async function accountNoticeFeed(accountId,{db=database()}={}){
 const [items,unread]=await Promise.all([
  db.query(`SELECT id,kind,resource_id,title,body,created_at,read_at
   FROM spdecode_shop.account_notices WHERE account_id=$1
   ORDER BY created_at DESC LIMIT 70`,[accountId]),
  db.query(`SELECT COUNT(*)::integer AS n FROM spdecode_shop.account_notices
   WHERE account_id=$1 AND read_at IS NULL`,[accountId])
 ]);
 return {notices:items.rows,unread:unread.rows[0]?.n||0};
}
export async function markAccountNotice(accountId,id,{db=database()}={}){
 if(!UUID.test(id||''))fail('INVALID_REQUEST');
 const res=await db.query(`UPDATE spdecode_shop.account_notices SET read_at=COALESCE(read_at,now())
   WHERE id=$1 AND account_id=$2 RETURNING id`,[id,accountId]);
 if(!res.rowCount)fail('NOTICE_NOT_FOUND',404);
 return {read:true};
}
export const accountNotificationsRequest=request=>safe(async()=>{
 const session=await requireAccount(request),id=session.user.id;
 if(request.method==='GET')return reply(await accountNoticeFeed(id));
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 requireOrigin(request);
 const body=await jsonBody(request,1200);
 if(!body||typeof body!=='object'||Array.isArray(body))fail('INVALID_REQUEST');
 const keys=Object.keys(body).sort().join(',');
 if(keys==='action,token'&&body.action==='register')
   return reply(await registerPush(id,body.token));
 if(keys==='action,token'&&body.action==='unregister')
   return reply(await unregisterPush(id,body.token));
 if(keys==='action,id'&&body.action==='read')
   return reply(await markAccountNotice(id,body.id));
 if(keys==='action'&&body.action==='read-all'){
   await database().query(`UPDATE spdecode_shop.account_notices SET read_at=now()
     WHERE account_id=$1 AND read_at IS NULL`,[id]);
   return reply({read:true});
 }
 fail('INVALID_REQUEST');
});
