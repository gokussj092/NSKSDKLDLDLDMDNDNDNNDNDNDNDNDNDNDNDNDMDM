import {test} from 'node:test';
import assert from 'node:assert/strict';
import {planFor,plansFor,validateProduct,validatePurchase,taxQuote,planAvailable,publicProduct} from '../lib/commerce/catalog.mjs';
const rules=[{country:'MX',region:'*',rateBps:1600,label:'IVA',reviewed:true}];
const api={id:'api-ip',enabled:true,prices:{USD:499},termPrices:{'1m':{USD:499},'2m':{USD:899},'6m':{USD:2499},'12m':{USD:3999}},days:30,quota:1000};
test('duration tiers preserve legacy prices and use only configured exact cents',()=>{
 const p=validateProduct(api);
 assert.equal(planFor(p,'base').prices.USD,499);
 assert.equal(planFor(p,'6m').days,180);
 assert.equal(planFor(p,'6m').prices.USD,2499);
 assert.equal(planFor(p,'3m').prices.USD,undefined);
 assert.deepEqual(plansFor(p).map(x=>x.id),['base','1m','2m','3m','6m','12m']);
 assert.throws(()=>planFor(p,'18m'),/INVALID_TERM/);
 assert.throws(()=>validateProduct({...api,termPrices:{'24m':{USD:499}}}),/INVALID_PRICE/);
 assert.throws(()=>validateProduct({...api,termPrices:{'6m':{USD:0}}}),/INVALID_PRICE/);
});
test('tax quote uses the selected term without inventing an exchange rate',()=>{
 const p=validateProduct(api);
 const q=taxQuote(p,'USD','MX','BC',rules,'6m');
 assert.equal(q.subtotal,2499);
 assert.equal(q.tax,400);
 assert.equal(q.total,2899);
 assert.throws(()=>taxQuote(p,'EUR','MX','BC',rules,'6m'),/CURRENCY_UNAVAILABLE/);
 assert.throws(()=>taxQuote(p,'USD','US','',rules,'6m'),/TAX_NOT_CONFIGURED/);
});
test('purchase term is validated and tied to the IP-bound product',()=>{
 const base={product:'api-ip',provider:'stripe',currency:'USD',country:'MX',region:'BC',version:1,idempotencyKey:'b4e3a486-a5b2-4e2b-8a31-4d4e8781b111',acceptedTerms:'2026-11-10',allowedIp:'1.1.1.1'};
 assert.equal(validatePurchase({...base,term:'12m'}).term,'12m');
 assert.equal(validatePurchase(base).term,'base');
 assert.throws(()=>validatePurchase({...base,term:'20m'}),/INVALID_REQUEST/);
 assert.throws(()=>validatePurchase({...base,allowedIp:'127.0.0.1'}),/PUBLIC_IP_REQUIRED/);
});
test('timed Offline remains disabled until APK compatibility is explicitly approved',()=>{
 const offline={id:'offline-3',enabled:true,prices:{USD:499},termPrices:{'1m':{USD:499}},maxDevices:3};
 const env={SPDECODE_STORE_ENABLED:'true',SPDECODE_OFFLINE_LICENSE_READY:'true',SPDECODE_OFFLINE_TIMED_LICENSE_READY:'false'};
 assert.equal(planAvailable(offline,'base',env),true);
 assert.equal(planAvailable(offline,'1m',env),false);
 const presented=publicProduct({settings:offline,version:3},{...env,STRIPE_SECRET_KEY:'sk_test_dummy',STRIPE_WEBHOOK_SECRET:'whsec_dummy',SPDECODE_PAYMENTS_LIVE:'false',SPDECODE_ACCOUNTS_ENABLED:'true',BETTER_AUTH_SECRET:'long-test-secret'.repeat(3),SPDECODE_DATABASE_URL:'synthetic',GOOGLE_CLIENT_ID:'test',GOOGLE_CLIENT_SECRET:'test'});
 assert.equal(presented.plans.find(p=>p.id==='1m').available,false);
});
