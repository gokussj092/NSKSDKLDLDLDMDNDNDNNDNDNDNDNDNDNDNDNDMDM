import {randomBytes,randomUUID,scrypt as scryptCb,createHmac,timingSafeEqual} from 'node:crypto';
import {promisify} from 'node:util';
import {database,transaction} from './db.mjs';
import {customRoles,roleCapabilities,roleExists} from './staff-roles.mjs';
import {fail} from './config.mjs';
import {adminSettings,authenticateAdmin,checkPassword} from '../c6-admin-auth.mjs';
import {opsStore} from '../c6-ops-store.mjs';
import {throttle} from '../c3-store.mjs';

const scrypt=promisify(scryptCb);
const USER=/^[a-z][a-z0-9._-]{2,47}$/;
const UUID=/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/;
const COOKIE='spdecode_staff_session',PREFIX='spdecode:staff:session:',TTL=3600;
export const STAFF_ROLES=Object.freeze(['admin','support','moderator','billing']);
export const STAFF_CAPABILITIES=Object.freeze({
 owner:['staff.read','staff.write','users.read','support.read','support.write','support.assign','audit.read','billing.read'],
 admin:['staff.read','users.read','support.read','support.write','support.assign','audit.read','billing.read'],
 support:['support.read','support.write'],
 moderator:['users.read','support.read','support.write','support.assign'],
 billing:['users.read','billing.read']
});
export function privileges(role){return STAFF_CAPABILITIES[role]||[];}
export function can(principal,cap){
 return !!principal && !principal.mustChangePassword &&
    (principal.capabilities||privileges(principal.role)).includes(cap);
}
export function safeStaff(row){
 return {id:row.id,username:row.username,name:row.display_name,role:row.role,
  enabled:row.enabled,mustChangePassword:row.must_change_password,
  lastLoginAt:row.last_login_at,createdAt:row.created_at,updatedAt:row.updated_at};
}
const nameValid=name=>typeof name==='string'&&name.trim().length>=2&&name.trim().length<=80&&
 !/[\u0000-\u001f\u007f]/.test(name);
const safeUser=v=>typeof v==='string'&&USER.test(v);
async function digestPassword(password){
 if(typeof password!=='string'||password.length<16||password.length>512)fail('INVALID_PASSWORD');
 const salt=randomBytes(16);
 const data=await scrypt(password,salt,64,{N:16384,r:8,p:1,maxmem:32*1024*1024});
 return 'scrypt$16384$8$1$'+salt.toString('hex')+'$'+data.toString('hex');
}
const generatedPassword=()=>randomBytes(24).toString('base64url');
const signer=(message,key)=>createHmac('sha256',key).update(message).digest('base64url');
export const staffCookie=(token,age=TTL)=>COOKIE+'='+token+'; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age='+age;
export const clearStaffCookie=()=>staffCookie('',0);
function parseCookie(request){
 const raw=request.headers.get('cookie')||'';
 if(raw.length>4096)return null;
 const found=raw.split(';').map(x=>x.trim()).filter(x=>x.startsWith(COOKIE+'='));
 return found.length===1?found[0].slice(COOKIE.length+1):null;
}
async function getStaffAuth(request,{db=database(),redis,config=adminSettings()}={}){
 if(!config.enabled)return null;
 const token=parseCookie(request);
 if(!token||token.length>1024||!/^[\w-]+\.[\w-]+$/.test(token))return null;
 const [body,tag]=token.split('.');
 const actual=Buffer.from(tag,'base64url'),expected=Buffer.from(signer(body,config.signingKey),'base64url');
 if(actual.length!==expected.length||!timingSafeEqual(actual,expected))return null;
 let claim;try{claim=JSON.parse(Buffer.from(body,'base64url').toString('utf8'));}catch{return null;}
 const now=Math.floor(Date.now()/1000);
 if(claim.aud!=='spdecode-staff-v1'||!UUID.test(claim.sub)||!UUID.test(claim.jti)||
   !Number.isInteger(claim.iat)||!Number.isInteger(claim.exp)||claim.exp<=now||
   claim.iat>now+5||claim.exp-claim.iat>TTL||!Number.isInteger(claim.version))return null;
 const source=redis||await opsStore();
 if(await source.get(PREFIX+claim.jti)!==claim.sub+':'+claim.version)return null;
 const result=await db.query(`SELECT id,username,display_name,role,enabled,must_change_password,
    session_version,last_login_at,created_at,updated_at
    FROM spdecode_shop.staff_accounts WHERE id=$1`,[claim.sub]);
 const row=result.rows[0];
 if(!row||!row.enabled||row.session_version!==claim.version)return null;
 const capabilities=row.role.startsWith('x_')?
   await roleCapabilities(row.role,db):privileges(row.role);
 if(capabilities===null)return null;
 return {id:row.id,username:row.username,name:row.display_name,role:row.role,
   mustChangePassword:row.must_change_password,sessionId:claim.jti,
   capabilities};
}
export async function panelPrincipal(request,{db=database(),redis,config=adminSettings()}={}){
 const source=redis||await opsStore();
 const owner=await authenticateAdmin(source,request,config);
 if(owner){
  return {id:owner.sub,username:config.username,
   name:(process.env.SPDECODE_SUPPORT_AGENT_NAME||config.username).trim().slice(0,80),
   role:'owner',mustChangePassword:false,capabilities:privileges('owner'),owner:true};
 }
 return getStaffAuth(request,{db,redis:source,config});
}
export async function requirePanel(request,permission,opts={}){
 const principal=await panelPrincipal(request,opts);
 if(!principal)fail('UNAUTHORIZED',401);
 if(permission&&!can(principal,permission))fail('FORBIDDEN',403);
 return principal;
}
export async function loginStaff(redis,username,password,{db=database(),config=adminSettings()}={}){
 if(!config.enabled)fail('ADMIN_DISABLED',503);
 const canonical=typeof username==='string'?username.trim().toLowerCase():'';
 const ok=await throttle(redis,'spdecode:staff:login:global',60,900);
 const scoped=await throttle(redis,'spdecode:staff:login:'+canonical.slice(0,48),8,900);
 if(!ok||!scoped)fail('RATE_LIMITED',429);
 if(!safeUser(canonical)||typeof password!=='string'||password.length<16||password.length>512)
   fail('INVALID_CREDENTIALS',401);
 const row=(await db.query(`SELECT * FROM spdecode_shop.staff_accounts WHERE username=$1`,[canonical])).rows[0];
 const valid=await checkPassword(password,row?.password_hash||config.passwordHash);
 if(!row||!valid||!row.enabled)fail('INVALID_CREDENTIALS',401);
 const issued=Math.floor(Date.now()/1000),jti=randomUUID();
 const claim={aud:'spdecode-staff-v1',sub:row.id,jti,iat:issued,exp:issued+TTL,version:row.session_version};
 const source=Buffer.from(JSON.stringify(claim)).toString('base64url');
 if(await redis.set(PREFIX+jti,row.id+':'+row.session_version,{EX:TTL,NX:true})!=='OK')fail('SERVICE_UNAVAILABLE',503);
 await db.query('UPDATE spdecode_shop.staff_accounts SET last_login_at=now() WHERE id=$1',[row.id]);
 return {token:source+'.'+signer(source,config.signingKey),role:row.role,
  mustChangePassword:row.must_change_password,expiresIn:TTL};
}
export async function logoutStaff(request,{db=database(),redis,config=adminSettings()}={}){
 const source=redis||await opsStore();
 const principal=await getStaffAuth(request,{db,redis:source,config});
 if(!principal)return false;
 await source.del(PREFIX+principal.sessionId);
 return true;
}
async function audit(client,principal,action,target,details={}){
 await client.query(`INSERT INTO spdecode_shop.staff_audit
 (id,actor_id,actor_role,action,target_id,details) VALUES($1,$2,$3,$4,$5,$6)`,
 [randomUUID(),principal.id,principal.role,action,String(target),JSON.stringify(details)]);
}
export async function listStaff({db=database()}={}){
 const rows=(await db.query(`SELECT id,username,display_name,role,enabled,
  must_change_password,last_login_at,created_at,updated_at
  FROM spdecode_shop.staff_accounts ORDER BY created_at DESC LIMIT 200`)).rows;
 const extras=(await customRoles({db})).roles;
 return {staff:rows.map(safeStaff),
   roles:[...STAFF_ROLES,...extras.filter(r=>r.enabled).map(r=>r.code)],
   roleDefinitions:extras};
}
export async function createStaff(principal,input,{db=database()}={}){
 if(principal.role!=='owner')fail('FORBIDDEN',403);
 if(!input||Object.keys(input).some(k=>!['username','name','role'].includes(k))||
    !safeUser(input.username)||!nameValid(input.name)||
    !(STAFF_ROLES.includes(input.role)||await roleExists(input.role,db)))
  fail('INVALID_STAFF');
 const password=generatedPassword(),hash=await digestPassword(password),id=randomUUID();
 try{
  await transaction(async client=>{
   await client.query(`INSERT INTO spdecode_shop.staff_accounts
     (id,username,display_name,role,password_hash) VALUES($1,$2,$3,$4,$5)`,
     [id,input.username,input.name.trim(),input.role,hash]);
   await audit(client,principal,'staff_created',id,{role:input.role,username:input.username});
  },db);
 }catch(e){if(e.code==='23505')fail('STAFF_USERNAME_TAKEN',409);throw e;}
 return {created:true,staff:{id,username:input.username,name:input.name.trim(),role:input.role},
  temporaryPassword:password};
}
export async function updateStaff(principal,input,{db=database()}={}){
 if(principal.role!=='owner')fail('FORBIDDEN',403);
 if(!input||!UUID.test(input.id)||
    Object.keys(input).some(k=>!['id','username','name','role','enabled','resetPassword'].includes(k))||
    (input.username!==undefined&&!safeUser(input.username))||
    (input.name!==undefined&&!nameValid(input.name))||
    (input.role!==undefined&&
      !(STAFF_ROLES.includes(input.role)||await roleExists(input.role,db)))||
    (input.enabled!==undefined&&typeof input.enabled!=='boolean')||
    (input.resetPassword!==undefined&&input.resetPassword!==true))fail('INVALID_STAFF');
 const temporary=input.resetPassword?generatedPassword():null;
 const digest=temporary?await digestPassword(temporary):null;
 let updated;
 try{
  await transaction(async client=>{
   const old=(await client.query(`SELECT * FROM spdecode_shop.staff_accounts WHERE id=$1 FOR UPDATE`,[input.id])).rows[0];
   if(!old)fail('STAFF_NOT_FOUND',404);
   updated=(await client.query(`UPDATE spdecode_shop.staff_accounts SET
     username=$2, display_name=$3,role=$4,enabled=$5,
     password_hash=COALESCE($6,password_hash),
     must_change_password=CASE WHEN $6 IS NULL THEN must_change_password ELSE true END,
     session_version=session_version+1,updated_at=now()
     WHERE id=$1 RETURNING id,username,display_name,role,enabled,must_change_password,
     last_login_at,created_at,updated_at`,
    [input.id,input.username??old.username,input.name?.trim()??old.display_name,
     input.role??old.role,input.enabled??old.enabled,digest])).rows[0];
   await audit(client,principal,'staff_updated',input.id,{role:updated.role,
     enabled:updated.enabled,credentialsReset:!!temporary});
  },db);
 }catch(e){if(e.code==='23505')fail('STAFF_USERNAME_TAKEN',409);throw e;}
 return {saved:true,staff:safeStaff(updated),...(temporary?{temporaryPassword:temporary}:{})};
}
export async function changeStaffPassword(principal,current,newPassword,{db=database()}={}){
 if(principal.owner||!UUID.test(principal.id))fail('FORBIDDEN',403);
 if(typeof current!=='string'||typeof newPassword!=='string'||newPassword.length<16||newPassword.length>128)
  fail('INVALID_PASSWORD');
 const hash=await digestPassword(newPassword);
 return transaction(async client=>{
  const row=(await client.query('SELECT * FROM spdecode_shop.staff_accounts WHERE id=$1 FOR UPDATE',[principal.id])).rows[0];
  if(!row||!row.enabled)fail('UNAUTHORIZED',401);
  if(!await checkPassword(current,row.password_hash))fail('INVALID_CREDENTIALS',403);
  await client.query(`UPDATE spdecode_shop.staff_accounts
   SET password_hash=$2,must_change_password=false,session_version=session_version+1,updated_at=now()
   WHERE id=$1`,[principal.id,hash]);
  await audit(client,principal,'staff_password_changed',principal.id);
  return {updated:true,reloginRequired:true};
 },db);
}
export async function recentStaffAudit({db=database()}={}){
 const items=(await db.query(`SELECT actor_id,actor_role,action,target_id,details,created_at
  FROM spdecode_shop.staff_audit ORDER BY created_at DESC LIMIT 150`)).rows;
 return {events:items};
}
