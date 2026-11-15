import {randomUUID} from 'node:crypto';
import {database,transaction} from './db.mjs';
import {requirePanel} from './staff.mjs';
import {safe,reply,fail,jsonBody,publicIp} from './config.mjs';
import {adminSettings,validMutation} from '../c6-admin-auth.mjs';

// The native panel uses the same sessions, capabilities and payment authority
// as the web panel. This endpoint never accepts a price or a paid/refund status.
const SECTIONS=new Set(['orders','entitlements','credits']);
const uuid=v=>typeof v==='string'&&/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(v);
export async function mobileRead(principal,section,page,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(!principal.capabilities?.includes('billing.read')||principal.mustChangePassword)fail('FORBIDDEN',403);
 if(!SECTIONS.has(section)||!Number.isInteger(page)||page<0||page>10000)fail('INVALID_REQUEST');
 const offset=page*50;
 const sources={
  orders:{table:'orders',sql:`SELECT o.id,o.account_id,o.product_id,o.provider,o.status,o.quote,o.product_snapshot,
    o.created_at,o.paid_at,o.payment_live,u.name,u.email,p.username
    FROM spdecode_shop.orders o LEFT JOIN shop_user u ON u.id=o.account_id
    LEFT JOIN spdecode_shop.profiles p ON p.account_id=o.account_id
    WHERE o.payment_live=$1 ORDER BY o.created_at DESC,o.id DESC LIMIT 50 OFFSET $2`},
  entitlements:{table:'entitlements',sql:`SELECT e.id,e.order_id,e.account_id,e.product_id,e.status,e.token_prefix,
    e.allowed_ip,e.quota,e.days,e.expires_at,e.claimed_at,e.created_at,e.payment_live,u.name,u.email,
    COALESCE((SELECT SUM(accepted) FROM spdecode_shop.usage WHERE entitlement_id=e.id),0)::integer AS requests
    FROM spdecode_shop.entitlements e LEFT JOIN shop_user u ON u.id=e.account_id
    WHERE e.payment_live=$1 ORDER BY e.created_at DESC,e.id DESC LIMIT 50 OFFSET $2`},
  credits:{table:'credit_ledger',sql:`SELECT c.id,c.account_id,c.movement_kind,c.delta,c.created_at,c.payment_live,u.name,u.email
    FROM spdecode_shop.credit_ledger c LEFT JOIN shop_user u ON u.id=c.account_id
    WHERE c.payment_live=$1 ORDER BY c.created_at DESC,c.id DESC LIMIT 50 OFFSET $2`}
 };
 const source=sources[section];
 const [rows,count]=await Promise.all([db.query(source.sql,[live,offset]),
   db.query(`SELECT COUNT(*)::integer AS count FROM spdecode_shop.${source.table} WHERE payment_live=$1`,[live])]);
 // Totals cover all orders, not only the loaded page. Never mix currencies.
 const totals=section==='orders'?(await db.query(`SELECT quote->>'currency' AS currency,
   SUM((quote->>'total')::bigint)::text AS cents,COUNT(*)::integer AS orders
   FROM spdecode_shop.orders WHERE payment_live=$1 AND status='paid'
   GROUP BY quote->>'currency' ORDER BY currency`,[live])).rows:undefined;
 return {items:rows.rows,count:count.rows[0]?.count??0,page,pageSize:50,live,...(totals?{totals}:{})};
}
export async function mobileMutation(principal,input,{db=database(),live=process.env.SPDECODE_PAYMENTS_LIVE==='true'}={}){
 if(principal.role!=='owner'||principal.mustChangePassword)fail('FORBIDDEN',403);
 if(!input||Array.isArray(input)||typeof input!=='object'||!uuid(input.id)||
    !['entitlement-status','api-ip'].includes(input.action))fail('INVALID_REQUEST');
 if(input.action==='entitlement-status'&&
    (Object.keys(input).sort().join(',')!=='action,id,status'||!['active','revoked'].includes(input.status)))fail('INVALID_REQUEST');
 if(input.action==='api-ip'&&
    (Object.keys(input).sort().join(',')!=='action,allowedIp,id'||!publicIp(input.allowedIp)))fail('INVALID_PUBLIC_IP');
 return transaction(async client=>{
   const row=(await client.query(`SELECT e.*,o.status AS order_status FROM spdecode_shop.entitlements e
    JOIN spdecode_shop.orders o ON o.id=e.order_id WHERE e.id=$1 AND e.payment_live=$2 FOR UPDATE OF e,o`,[input.id,live])).rows[0];
   if(!row)fail('ENTITLEMENT_NOT_FOUND',404);
   if(input.action==='api-ip'&&row.product_id!=='api-ip')fail('INVALID_REQUEST');
   if((input.action==='api-ip'||input.status==='active')&&
      (row.order_status!=='paid'||row.expires_at&&new Date(row.expires_at)<=new Date()))fail('ENTITLEMENT_NOT_ACTIVE',409);
   if(input.action==='api-ip')await client.query('UPDATE spdecode_shop.entitlements SET allowed_ip=$2 WHERE id=$1',[row.id,publicIp(input.allowedIp)]);
   else await client.query('UPDATE spdecode_shop.entitlements SET status=$2 WHERE id=$1',[row.id,input.status]);
   await client.query(`INSERT INTO spdecode_shop.staff_audit(id,actor_id,actor_role,action,target_id,details)
     VALUES($1,$2,$3,$4,$5,$6)`,[randomUUID(),principal.id,principal.role,input.action,row.id,
     JSON.stringify(input.action==='api-ip'?{ipChanged:true}:{status:input.status})]);
   return {saved:true,id:row.id};
 },db);
}
export const mobileAdminRequest=(request,options={})=>safe(async()=>{
 const principal=await (options.authorize||requirePanel)(request,request.method==='GET'?'billing.read':null);
 if(request.method==='GET'){
  const params=new URL(request.url).searchParams;
  if([...params.keys()].some(k=>!['section','page'].includes(k))||!/^(0|[1-9]\d{0,4})$/.test(params.get('page')||'0'))fail('INVALID_REQUEST');
  return reply(await mobileRead(principal,params.get('section'),Number(params.get('page')||0),options));
 }
 if(request.method!=='POST')fail('METHOD_NOT_ALLOWED',405);
 if(!validMutation(request,adminSettings()))fail('CSRF_REJECTED',403);
 return reply(await mobileMutation(principal,await jsonBody(request,2048),options));
});
