import {randomBytes} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {normalizeHandle,normalizeDisplayName} from '../f7-account-identity.mjs';
import {fail} from './config.mjs';
export async function profile(accountId,db=database()){
  await db.query('INSERT INTO spdecode_shop.profiles(account_id,username) VALUES($1,$2) ON CONFLICT(account_id) DO NOTHING',
    [accountId,'u_'+randomBytes(10).toString('hex')]);
  return (await db.query('SELECT username FROM spdecode_shop.profiles WHERE account_id=$1',[accountId])).rows[0];
}
export async function editProfile(accountId,body,db=database()){
  const handle=normalizeHandle(body?.username),name=normalizeDisplayName(body?.name);
  if(!handle||!name)fail('INVALID_PROFILE');
  try{return await transaction(async client=>{
    await profile(accountId,client);
    const old=(await client.query('SELECT * FROM spdecode_shop.profiles WHERE account_id=$1 FOR UPDATE',[accountId])).rows[0];
    if(old.username!==handle){
      if(old.handle_changed_at&&Date.now()-new Date(old.handle_changed_at).getTime()<7*86400000)fail('HANDLE_CHANGE_LIMIT',429);
      await client.query('INSERT INTO spdecode_shop.reserved_handles(username,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[handle,accountId]);
      const reserved=(await client.query('SELECT account_id FROM spdecode_shop.reserved_handles WHERE username=$1 FOR UPDATE',[handle])).rows[0];
      if(reserved&&reserved.account_id!==accountId)fail('USERNAME_TAKEN',409);
      await client.query('INSERT INTO spdecode_shop.reserved_handles(username,account_id) VALUES($1,$2) ON CONFLICT DO NOTHING',[old.username,accountId]);
      await client.query('UPDATE spdecode_shop.profiles SET username=$2,handle_changed_at=now() WHERE account_id=$1',[accountId,handle]);
    }
    await client.query('UPDATE shop_user SET name=$2,"updatedAt"=now() WHERE id=$1',[accountId,name]);
    return {username:handle,name};
  },db);}catch(e){if(e.code==='23505')fail('USERNAME_TAKEN',409);throw e;}
}
