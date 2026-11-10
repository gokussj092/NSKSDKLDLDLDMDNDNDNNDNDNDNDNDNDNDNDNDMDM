import {randomBytes} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {normalizeHandle,normalizeDisplayName} from '../f7-account-identity.mjs';
import {fail} from './config.mjs';

const NAME_MAX=80,BIO_MAX=180,IMAGE_MAX=85000;
function avatarInput(value){
 if(value===undefined)return undefined;
 if(value===null)return null;
 if(typeof value!=='string'||value.length>115000)fail('INVALID_AVATAR');
 const match=/^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
 if(!match)fail('INVALID_AVATAR');
 const data=Buffer.from(match[1],'base64');
 if(data.length<100||data.length>IMAGE_MAX||data[0]!==0xff||data[1]!==0xd8||
   data[data.length-2]!==0xff||data[data.length-1]!==0xd9||
   data.toString('base64')!==match[1])fail('INVALID_AVATAR');
 return value;
}
export async function profile(accountId,db=database()){
 await db.query('INSERT INTO spdecode_shop.profiles(account_id,username) VALUES($1,$2) ON CONFLICT(account_id) DO NOTHING',
   [accountId,'u_'+randomBytes(10).toString('hex')]);
 return (await db.query('SELECT username,bio,avatar_data FROM spdecode_shop.profiles WHERE account_id=$1',[accountId])).rows[0];
}
export async function editProfile(accountId,body,db=database()){
 if(!body||typeof body!=='object'||Array.isArray(body)||
   Object.keys(body).some(k=>!['username','name','bio','avatarData'].includes(k)))fail('INVALID_PROFILE');
 const handle=normalizeHandle(body.username),name=normalizeDisplayName(body.name);
 if(!handle||!name||name.length>NAME_MAX||
   typeof body.bio!=='string'||body.bio.length>BIO_MAX||
   /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(body.bio))fail('INVALID_PROFILE');
 const bio=body.bio.trim(),avatar=avatarInput(body.avatarData);
 try{return await transaction(async client=>{
   await profile(accountId,client);
   const old=(await client.query('SELECT * FROM spdecode_shop.profiles WHERE account_id=$1 FOR UPDATE',[accountId])).rows[0];
   if(old.username!==handle){
     if(old.handle_changed_at&&Date.now()-new Date(old.handle_changed_at).getTime()<7*86400000)fail('HANDLE_CHANGE_LIMIT',429);
     await client.query('INSERT INTO spdecode_shop.reserved_handles(username,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[handle,accountId]);
     const reserved=(await client.query('SELECT account_id FROM spdecode_shop.reserved_handles WHERE username=$1 FOR UPDATE',[handle])).rows[0];
     if(reserved&&reserved.account_id!==accountId)fail('USERNAME_TAKEN',409);
     await client.query('INSERT INTO spdecode_shop.reserved_handles(username,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[old.username,accountId]);
   }
   await client.query('UPDATE spdecode_shop.profiles SET username=$2,handle_changed_at=CASE WHEN username<>$2 THEN now() ELSE handle_changed_at END,bio=$3 WHERE account_id=$1',
     [accountId,handle,bio]);
   if(avatar===null)await client.query('UPDATE spdecode_shop.profiles SET avatar_data=NULL WHERE account_id=$1',[accountId]);
   else if(avatar!==undefined)await client.query('UPDATE spdecode_shop.profiles SET avatar_data=$2 WHERE account_id=$1',[accountId,avatar]);
   await client.query('UPDATE shop_user SET name=$2,"updatedAt"=now() WHERE id=$1',[accountId,name]);
   return {username:handle,name,bio};
 },db);}catch(e){if(e.code==='23505')fail('USERNAME_TAKEN',409);throw e;}
}
