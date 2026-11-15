import {test,before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {makeAuth} from '../lib/commerce/auth.mjs';
import {createGift,disableGift,listGifts,redeemGift,validateGiftSpec} from '../lib/commerce/gifts.mjs';
import {creditBalance} from '../lib/commerce/credits.mjs';
import {claim} from '../lib/commerce/orders.mjs';

let embedded,db,auth;
const users=[randomUUID(),randomUUID(),randomUUID()];
const env={...process.env,NODE_ENV:'test',CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000',
 SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgres://synthetic',
 SPDECODE_PAYMENTS_LIVE:'false',SPDECODE_STORE_ENABLED:'false',
 BETTER_AUTH_SECRET:'test-password-gift-auth-secret-'.repeat(3),
 GOOGLE_CLIENT_ID:'test.apps.googleusercontent.com',GOOGLE_CLIENT_SECRET:'synthetic',
 SPDECODE_SHOP_TOKEN_KEY:'test-gift-hmac-key-material-'.repeat(3)};
Object.assign(process.env,env);

before(async()=>{
 embedded=new PGlite();
 const query=async(sql,params=[])=>{
   const r=await embedded.query(sql,params);
   return {rows:r.rows,rowCount:r.rows.length || r.affectedRows || 0};
 };
 db={query,connect:async()=>({query,release(){}})};
 auth=makeAuth(db,env);
 const migration=await getMigrations(auth.options);
 await migration.runMigrations();
 for(const filename of ['002_shop.sql','003_ads_free.sql','004_gifts.sql']){
   const sql=await readFile(new URL('../sql/'+filename,import.meta.url),'utf8');
   await embedded.exec(sql);
 }
 for(const [i,id] of users.entries()){
   await db.query(`INSERT INTO shop_user(id,name,email,"emailVerified","createdAt","updatedAt")
     VALUES($1,$2,$3,true,now(),now())`,[id,'Gift recipient '+i,id+'@example.invalid']);
   await db.query(`INSERT INTO spdecode_shop.profiles(account_id,username,bio)
     VALUES($1,$2,'')`,[id,'giftuser_'+i]);
 }
});
after(async()=>{await embedded?.close();});

test('90-day rolling Better Auth sessions and password enrollment are configured without public signup',()=>{
 assert.equal(auth.options.session.expiresIn,90*86400);
 assert.equal(auth.options.session.updateAge,43200);
 assert.equal(auth.options.emailAndPassword.enabled,true);
 assert.equal(auth.options.emailAndPassword.disableSignUp,true);
 assert.equal(auth.options.emailAndPassword.requireEmailVerification,true);
});

test('gift schema validates benefits and usage caps',()=>{
 assert.equal(validateGiftSpec({title:'Community',kind:'ads-free',days:365,maxUses:5}).days,365);
 assert.throws(()=>validateGiftSpec({title:'x',kind:'credits',credits:3,maxUses:2}),/INVALID_GIFT/);
 assert.throws(()=>validateGiftSpec({title:'Community',kind:'credits',credits:0,maxUses:2}),/INVALID_GIFT/);
 assert.throws(()=>validateGiftSpec({title:'Community',kind:'ads-free',days:31,maxUses:0}),/INVALID_GIFT/);
 assert.throws(()=>validateGiftSpec({title:'Community',kind:'api-ip',days:30,maxUses:2}),/INVALID_GIFT/);
});

test('credits reward is signed by server, limited to distinct users and tracked by profile',async()=>{
 const result=await createGift({title:'Community credits',kind:'credits',credits:7,maxUses:2},'admin-qa',{db});
 assert.match(result.code,/^SPG-[A-Za-z0-9_-]{22}$/);
 const stored=(await db.query('SELECT * FROM spdecode_shop.gift_codes WHERE id=$1',[result.id])).rows[0];
 assert.notEqual(stored.code_digest,result.code);
 assert.ok(!JSON.stringify(stored).includes(result.code));
 const a=await redeemGift(users[0],result.code,{db});
 assert.equal(a.product,'analysis-credits');
 assert.equal((await creditBalance(users[0],{db,live:false})).available,7);
 await assert.rejects(redeemGift(users[0],result.code,{db}),/GIFT_ALREADY_REDEEMED/);
 const b=await redeemGift(users[1],result.code,{db});
 assert.equal(b.credits,7);
 await assert.rejects(redeemGift(users[2],result.code,{db}),/GIFT_INVALID/);
 const list=await listGifts({db});
 assert.equal(list.codes.find(x=>x.id===result.id).used,2);
 assert.equal(list.redemptions.filter(x=>x.gift_id===result.id).length,2);
 assert.ok(list.redemptions.some(x=>x.username==='giftuser_0'&&x.name==='Gift recipient 0'));
 assert.ok(!JSON.stringify(list).includes(result.code));
});

test('ad-free codes grant signed 30/60/365-day entitlements without checkout',async()=>{
 const one=await createGift({title:'A month ad free',kind:'ads-free',days:30,maxUses:1},'admin-qa',{db});
 const two=await createGift({title:'Two months ad free',kind:'ads-free',days:60,maxUses:1},'admin-qa',{db});
 await redeemGift(users[0],one.code,{db});
 await redeemGift(users[0],two.code,{db});
 const ent=(await db.query(`SELECT * FROM spdecode_shop.entitlements
   WHERE account_id=$1 AND product_id='ads-free' ORDER BY expires_at DESC`,[users[0]])).rows;
 assert.equal(ent.length,2);
 assert.ok(new Date(ent[0].expires_at).getTime()>Date.now()+89*86400000);
 await assert.rejects(claim(users[0],ent[0].id,{db}),/CLAIM_UNAVAILABLE/);
 const purchased=(await db.query(`SELECT provider,status,quote FROM spdecode_shop.orders
    WHERE id=$1`,[(await db.query(`SELECT order_id FROM spdecode_shop.entitlements WHERE id=$1`,[ent[0].id])).rows[0].order_id])).rows[0];
 assert.equal(purchased.provider,'gift');
 assert.equal(purchased.quote.total,0);
});

test('offline license is time-limited, account-bound and claimable once',async()=>{
 const code=await createGift({title:'Offline access',kind:'offline-3',days:30,maxUses:1},'admin-qa',{db});
 const redeemed=await redeemGift(users[1],code.code,{db});
 const ent=(await db.query('SELECT * FROM spdecode_shop.entitlements WHERE order_id=$1',[redeemed.orderId])).rows[0];
 assert.equal(ent.product_id,'offline-3');
 assert.equal(ent.days,30);
 const claimed=await claim(users[1],ent.id,{db});
 assert.match(claimed.token,/^SPD-OFF-/);
 await assert.rejects(claim(users[1],ent.id,{db}),/ALREADY_REVEALED/);
 await assert.rejects(claim(users[0],ent.id,{db}),/PURCHASE_NOT_AVAILABLE/);
});

test('disabled codes and account-bound brute-force limits reject new redemptions',async()=>{
 const disabled=await createGift({title:'Disabled gift',kind:'credits',credits:1,maxUses:1},'admin-qa',{db});
 await disableGift(disabled.id,'admin-qa',{db});
 await assert.rejects(redeemGift(users[2],disabled.code,{db}),/GIFT_INVALID/);
 for(let i=0;i<6;i++)await assert.rejects(redeemGift(users[2],'SPG-'+('A'.repeat(21))+i,{db}),/GIFT_INVALID/);
 await assert.rejects(redeemGift(users[2],disabled.code,{db}),/GIFT_RATE_LIMITED/);
});
