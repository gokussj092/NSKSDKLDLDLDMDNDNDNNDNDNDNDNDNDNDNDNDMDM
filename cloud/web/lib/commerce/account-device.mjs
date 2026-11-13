import {randomBytes,randomUUID,createHash,createPublicKey,verify} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail} from './config.mjs';
const idRE=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const b64=/^[A-Za-z0-9_-]{40,3000}$/;
function keyObject(value){
 if(typeof value!=='string'||!b64.test(value))fail('DEVICE_KEY_INVALID');
 try{
  const key=createPublicKey({key:Buffer.from(value,'base64url'),format:'der',type:'spki'});
  if(key.asymmetricKeyType!=='ec'||key.asymmetricKeyDetails?.namedCurve!=='prime256v1')
    fail('DEVICE_KEY_INVALID');
  return key;
 }catch{fail('DEVICE_KEY_INVALID');}
}
function signature(value){
 if(typeof value!=='string'||!b64.test(value))fail('DEVICE_SIGNATURE_INVALID');
 return Buffer.from(value,'base64url');
}
const digest=v=>createHash('sha256').update(v).digest('hex');
export async function registerDevice(accountId,input,{db=database()}={}){
 if(!input||Object.keys(input).some(k=>!['keyId','publicKey','signature'].includes(k))||
   !idRE.test(input.keyId))fail('INVALID_REQUEST');
 const key=keyObject(input.publicKey);
 const phrase='SPDECODE-DEVICE-REGISTER-v1:'+accountId+':'+input.keyId;
 if(!verify('sha256',Buffer.from(phrase),key,signature(input.signature)))
  fail('DEVICE_SIGNATURE_INVALID',403);
 return transaction(async client=>{
  const owner=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId]);
  if(!owner.rowCount)fail('SIGN_IN_REQUIRED',401);
  const existing=await client.query('SELECT public_key FROM spdecode_shop.account_device_keys WHERE account_id=$1 AND key_id=$2',[accountId,input.keyId]);
  if(existing.rowCount&&existing.rows[0].public_key!==input.publicKey)fail('DEVICE_KEY_CONFLICT',409);
  const count=await client.query('SELECT COUNT(*)::integer AS n FROM spdecode_shop.account_device_keys WHERE account_id=$1',[accountId]);
  if(count.rows[0].n>=5&&!existing.rowCount)fail('DEVICE_KEY_LIMIT',409);
  await client.query(`INSERT INTO spdecode_shop.account_device_keys(account_id,key_id,public_key)
    VALUES($1,$2,$3) ON CONFLICT(account_id,key_id) DO NOTHING`,[accountId,input.keyId,input.publicKey]);
  return {registered:true};
 },db);
}
export async function makeDeletionChallenge(accountId,keyId,{db=database()}={}){
 if(!idRE.test(keyId))fail('INVALID_REQUEST');
 return transaction(async client=>{
  const device=await client.query('SELECT key_id FROM spdecode_shop.account_device_keys WHERE account_id=$1 AND key_id=$2',[accountId,keyId]);
  if(!device.rowCount)fail('DEVICE_KEY_NOT_REGISTERED',403);
  const id=randomUUID(),nonce=randomBytes(32).toString('base64url');
  const phrase='SPDECODE-DELETE-v1:'+accountId+':'+id+':'+nonce;
  await client.query(`INSERT INTO spdecode_shop.account_challenges
    (id,account_id,key_id,purpose,challenge_digest,expires_at)
    VALUES($1,$2,$3,'delete-account',$4,now()+interval '2 minutes')`,
    [id,accountId,keyId,digest(phrase)]);
  return {challengeId:id,challenge:phrase};
 },db);
}
export async function authorizeDeviceDeletion(accountId,input,{db=database()}={}){
 if(!idRE.test(input?.keyId)||!idRE.test(input?.challengeId))fail('INVALID_REQUEST');
 return transaction(async client=>{
  const challenge=(await client.query(`SELECT c.*,d.public_key FROM spdecode_shop.account_challenges c
    JOIN spdecode_shop.account_device_keys d
      ON d.account_id=c.account_id AND d.key_id=c.key_id
    WHERE c.account_id=$1 AND c.id=$2 AND c.key_id=$3 FOR UPDATE OF c`,
    [accountId,input.challengeId,input.keyId])).rows[0];
  if(!challenge||challenge.used_at||new Date(challenge.expires_at)<=new Date())fail('CHALLENGE_EXPIRED',403);
  const phrase=input.challenge;
  if(typeof phrase!=='string'||phrase.length>200||
     digest(phrase)!==challenge.challenge_digest)fail('CHALLENGE_INVALID',403);
  if(!verify('sha256',Buffer.from(phrase),keyObject(challenge.public_key),signature(input.signature)))
    fail('DEVICE_SIGNATURE_INVALID',403);
  await client.query('UPDATE spdecode_shop.account_challenges SET used_at=now() WHERE id=$1',[challenge.id]);
  return {verified:true};
 },db);
}
export async function deleteAccountData(accountId,{db=database()}={}){
 return transaction(async client=>{
  const user=await client.query('SELECT id FROM shop_user WHERE id=$1 FOR UPDATE',[accountId]);
  if(!user.rowCount)fail('SIGN_IN_REQUIRED',401);
  await client.query(`UPDATE spdecode_shop.entitlements SET status='revoked',
    token_digest=NULL,token_prefix=NULL,allowed_ip=NULL WHERE account_id=$1`,[accountId]);
  await client.query(`UPDATE spdecode_shop.orders SET allowed_ip=NULL,request_digest='account-deleted'
    WHERE account_id=$1`,[accountId]);
  await client.query('DELETE FROM spdecode_shop.reserved_handles WHERE account_id=$1',[accountId]);
  // History retained for accounting without identifiable messages and tokens.
  await client.query('DELETE FROM shop_user WHERE id=$1',[accountId]);
  return {deleted:true};
 },db);
}
