import {randomUUID} from 'node:crypto';
import {database} from './db.mjs';
import {fail} from './config.mjs';
const MAX=30;
const LIVE=()=>process.env.SPDECODE_PAYMENTS_LIVE==='true';
const validId=x=>typeof x==='string'&&x.length>=8&&x.length<=80&&/^[\w-]+$/.test(x);
export async function userDirectory({search='',page=0,db=database()}={}){
 if(typeof search!=='string'||search.length>80||!Number.isInteger(page)||page<0||page>1000)
  fail('INVALID_REQUEST');
 const term=search.trim(),pattern='%'+term.replace(/[\\%_]/g,'\\$&')+'%';
 const params=[term,pattern,MAX,page*MAX,LIVE()];
 const where=`($1='' OR u.name ILIKE $2 ESCAPE '\\' OR u.email ILIKE $2 ESCAPE '\\'
  OR p.username ILIKE $2 ESCAPE '\\' OR u.id ILIKE $2 ESCAPE '\\')`;
 const [count,result]=await Promise.all([
  db.query(`SELECT COUNT(*)::integer AS count FROM shop_user u
   LEFT JOIN spdecode_shop.profiles p ON p.account_id=u.id WHERE ${where}`,params.slice(0,2)),
  db.query(`SELECT u.id,u.name,u.email,u.image,u."emailVerified" AS email_verified,
   u."createdAt" AS created_at,u."updatedAt" AS updated_at,
   p.username,COALESCE(p.avatar_data,u.image) AS avatar,
   (SELECT string_agg(DISTINCT i."providerId",',') FROM shop_identity i WHERE i."userId"=u.id) AS providers,
   EXISTS(SELECT 1 FROM shop_identity i WHERE i."userId"=u.id
     AND i."providerId"='credential' AND i.password IS NOT NULL) AS password_enabled,
   (SELECT MAX(s."updatedAt") FROM shop_session s WHERE s."userId"=u.id) AS last_session_at,
   (SELECT COUNT(*)::integer FROM spdecode_shop.orders o WHERE o.account_id=u.id) AS orders_count,
   (SELECT COUNT(*)::integer FROM spdecode_shop.support_threads t
     WHERE t.account_id=u.id AND t.status<>'closed') AS open_tickets,
   COALESCE((SELECT SUM(c.delta) FROM spdecode_shop.credit_ledger c
     WHERE c.account_id=u.id AND c.payment_live=$5),0)::integer AS credits,
   EXISTS(SELECT 1 FROM spdecode_shop.entitlements e
     WHERE e.account_id=u.id AND e.product_id='ads-free'
       AND e.status='active' AND e.payment_live=$5 AND e.expires_at>now()) AS ad_free
   FROM shop_user u LEFT JOIN spdecode_shop.profiles p ON p.account_id=u.id
   WHERE ${where} ORDER BY u."createdAt" DESC,u.id DESC LIMIT $3 OFFSET $4`,params)
 ]);
 return {count:count.rows[0]?.count??0,page,pageSize:MAX,users:result.rows};
}
export async function userDetail(principal,id,{db=database()}={}){
 if(!validId(id))fail('INVALID_REQUEST');
 const user=(await db.query(`SELECT u.id,u.name,u.email,u.image,
  u."emailVerified" AS email_verified,u."createdAt" AS created_at,
  u."updatedAt" AS updated_at,p.username,p.bio,
  COALESCE(p.avatar_data,u.image) AS avatar,p.handle_changed_at
  FROM shop_user u LEFT JOIN spdecode_shop.profiles p ON p.account_id=u.id
  WHERE u.id=$1`,[id])).rows[0];
 if(!user)fail('USER_NOT_FOUND',404);
 const [identities,orders,entitlements,redemptions,tickets,sessions,ledger]=await Promise.all([
  db.query(`SELECT "providerId" AS provider_id, "createdAt" AS linked_at,
     (password IS NOT NULL) AS password_set FROM shop_identity
     WHERE "userId"=$1`,[id]),
  db.query(`SELECT id,product_id,status,provider,quote,created_at,paid_at,
     payment_live FROM spdecode_shop.orders WHERE account_id=$1 ORDER BY created_at DESC LIMIT 40`,[id]),
  db.query(`SELECT id,product_id,status,expires_at,allowed_ip,created_at,
     payment_live FROM spdecode_shop.entitlements WHERE account_id=$1
     ORDER BY created_at DESC LIMIT 40`,[id]),
  db.query(`SELECT g.title,g.kind,r.created_at FROM spdecode_shop.gift_redemptions r
     JOIN spdecode_shop.gift_codes g ON g.id=r.gift_id WHERE r.account_id=$1
     ORDER BY r.created_at DESC LIMIT 30`,[id]),
  db.query(`SELECT id,subject,category,status,created_at,last_message_at
     FROM spdecode_shop.support_threads WHERE account_id=$1
     ORDER BY created_at DESC LIMIT 30`,[id]),
  db.query(`SELECT COUNT(*)::integer AS total,MAX("updatedAt") AS last_active
     FROM shop_session WHERE "userId"=$1`,[id]),
  db.query(`SELECT movement_kind,delta,created_at FROM spdecode_shop.credit_ledger
     WHERE account_id=$1 AND payment_live=$2 ORDER BY created_at DESC LIMIT 40`,[id,LIVE()])
 ]);
 await db.query(`INSERT INTO spdecode_shop.staff_audit
  (id,actor_id,actor_role,action,target_id) VALUES($1,$2,$3,'customer_viewed',$4)`,
  [randomUUID(),principal.id,principal.role,id]);
 return {user,identities:identities.rows,orders:orders.rows,
  entitlements:entitlements.rows,redemptions:redemptions.rows,tickets:tickets.rows,
  sessions:sessions.rows[0],creditMovements:ledger.rows};
}
