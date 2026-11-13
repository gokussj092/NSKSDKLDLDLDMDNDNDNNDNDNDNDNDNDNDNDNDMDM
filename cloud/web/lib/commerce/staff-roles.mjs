import {randomUUID} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {fail} from './config.mjs';
export const CUSTOM_PERMISSION_KEYS=Object.freeze([
 'users.read','support.read','support.write','support.assign','billing.read'
]);
const CODES=/^x_[a-z][a-z0-9_]{1,12}$/;
function valid(input){
 if(!input||typeof input!=='object'||Array.isArray(input)||
  Object.keys(input).some(k=>!['action','code','name','permissions','enabled'].includes(k))||
  !['create','update'].includes(input.action)||!CODES.test(input.code||'')||
  typeof input.name!=='string'||input.name.trim().length<3||input.name.trim().length>72||
  !Array.isArray(input.permissions)||input.permissions.length>5||
  new Set(input.permissions).size!==input.permissions.length||
  input.permissions.some(p=>!CUSTOM_PERMISSION_KEYS.includes(p))||
  input.enabled!==undefined&&typeof input.enabled!=='boolean)fail('INVALID_ROLE',400);
 const ps=new Set(input.permissions);
 if((ps.has('support.write')||ps.has('support.assign'))&&!ps.has('support.read'))
  fail('ROLE_REQUIRES_SUPPORT_READ',400);
}
export async function customRoles({db=database()}={}){
 const rows=(await db.query(`SELECT code,name,permissions,enabled,created_at,updated_at
  FROM spdecode_shop.staff_custom_roles ORDER BY created_at ASC LIMIT 100`)).rows;
 return {roles:rows};
}
export async function roleCapabilities(code,db=database()){
 if(typeof code!=='string'||!CODES.test(code))return null;
 const row=(await db.query(`SELECT permissions FROM spdecode_shop.staff_custom_roles
  WHERE code=$1 AND enabled=true`,[code])).rows[0];
 return row?.permissions?.filter(x=>CUSTOM_PERMISSION_KEYS.includes(x))||null;
}
export async function roleExists(code,db=database()){
 return (await roleCapabilities(code,db))!==null;
}
export async function writeCustomRole(principal,input,{db=database()}={}){
 if(principal?.role!=='owner')fail('FORBIDDEN',403);
 valid(input);
 return transaction(async client=>{
  if(input.action==='create'){
   const added=await client.query(`INSERT INTO spdecode_shop.staff_custom_roles
    (code,name,permissions,enabled) VALUES($1,$2,$3,$4)
    ON CONFLICT(code) DO NOTHING RETURNING code`,
    [input.code,input.name.trim(),input.permissions,input.enabled??true]);
   if(!added.rowCount)fail('ROLE_EXISTS',409);
  }else{
   const updated=await client.query(`UPDATE spdecode_shop.staff_custom_roles
    SET name=$2,permissions=$3,enabled=$4,updated_at=now()
    WHERE code=$1 RETURNING code`,
    [input.code,input.name.trim(),input.permissions,input.enabled??true]);
   if(!updated.rowCount)fail('ROLE_NOT_FOUND',404);
   // Immediately invalidate sessions for changed role holders. Sessions
   // revalidate against this table on every request as an additional guard.
   await client.query(`UPDATE spdecode_shop.staff_accounts
    SET session_version=session_version+1,updated_at=now() WHERE role=$1`,[input.code]);
  }
  await client.query(`INSERT INTO spdecode_shop.staff_audit
   (id,actor_id,actor_role,action,target_id,details) VALUES($1,$2,$3,$4,$5,$6)`,
   [randomUUID(),principal.id,'owner','staff_role_'+input.action,input.code,
    JSON.stringify({permissions:input.permissions,enabled:input.enabled??true})]);
  return {saved:true,role:{code:input.code,name:input.name.trim(),
   permissions:input.permissions,enabled:input.enabled??true}};
 },db);
}
