import {test} from 'node:test';
import assert from 'node:assert/strict';
import {authReady,paymentReady,providerConfigured,requireOrigin,siteOrigin} from '../lib/commerce/config.mjs';
const configured={SPDECODE_ACCOUNTS_ENABLED:'true',SPDECODE_DATABASE_URL:'postgresql://synthetic-only',
 BETTER_AUTH_SECRET:'synthetic-secret-'.repeat(3),GOOGLE_CLIENT_ID:'synthetic-client',GOOGLE_CLIENT_SECRET:'synthetic-secret',
 SPDECODE_STORE_ENABLED:'true',SPDECODE_SHOP_TOKEN_KEY:'synthetic-token-key-'.repeat(3),SPDECODE_PAYMENTS_LIVE:'false',
 STRIPE_SECRET_KEY:'sk_test_synthetic',STRIPE_WEBHOOK_SECRET:'whsec_synthetic'};
test('customer accounts and checkout require explicit opt-in and all independent configuration',()=>{
 assert.equal(authReady({}),false);assert.equal(paymentReady('stripe',{}),false);
 assert.equal(authReady(configured),true);assert.equal(paymentReady('stripe',configured),true);
 for(const key of ['SPDECODE_ACCOUNTS_ENABLED','SPDECODE_DATABASE_URL','BETTER_AUTH_SECRET','GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET']){
  const incomplete={...configured,[key]:''};assert.equal(authReady(incomplete),false);assert.equal(paymentReady('stripe',incomplete),false);
 }
 assert.equal(paymentReady('stripe',{...configured,SPDECODE_STORE_ENABLED:'false'}),false);
 assert.equal(paymentReady('stripe',{...configured,SPDECODE_SHOP_TOKEN_KEY:''}),false);
 assert.equal(paymentReady('stripe',{...configured,SPDECODE_PAYMENTS_LIVE:'true'}),false);
 assert.equal(providerConfigured('stripe',{...configured,SPDECODE_STORE_ENABLED:'false',GOOGLE_CLIENT_ID:''}),true);
 assert.equal(providerConfigured('mercadopago',{...configured,MERCADOPAGO_ACCESS_TOKEN:'APP_USR-synthetic',MERCADOPAGO_WEBHOOK_SECRET:'synthetic'}),false);
});
test('production account origin cannot use plaintext HTTP or client-supplied redirect origins',()=>{
 assert.throws(()=>siteOrigin({NODE_ENV:'production',CLOUD_SITE_PUBLIC_ORIGIN:'http://localhost:3000'}),/SITE_NOT_CONFIGURED/);
 assert.throws(()=>siteOrigin({NODE_ENV:'production',CLOUD_SITE_PUBLIC_ORIGIN:'https://spdecode.xyz/redirect'}),/SITE_NOT_CONFIGURED/);
 const origin=siteOrigin();
 assert.doesNotThrow(()=>requireOrigin(new Request(origin+'/api/store/checkout',{headers:{origin,'sec-fetch-site':'same-origin'}})));
 assert.throws(()=>requireOrigin(new Request(origin+'/api/store/checkout',{headers:{origin:'https://untrusted.invalid','sec-fetch-site':'cross-site'}})),/CSRF_REJECTED/);
 assert.throws(()=>requireOrigin(new Request(origin+'/api/store/checkout')),/CSRF_REJECTED/);
});
