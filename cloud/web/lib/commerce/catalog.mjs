import {fail,publicIp,paymentReady} from './config.mjs';
export const PRODUCT_IDS=['offline-3','api-ip','analysis-credits'];
export const TERMS={'1m':1,'2m':2,'3m':3,'6m':6,'12m':12};
export const CREDIT_PACKS={'1c':1,'5c':5,'10c':10,'25c':25,'50c':50,'100c':100};
export const CURRENCIES=['USD','MXN','EUR'];
function validPrices(prices){
 return prices&&typeof prices==='object'&&!Array.isArray(prices)&&
   Object.keys(prices).every(k=>CURRENCIES.includes(k))&&
   Object.values(prices).every(n=>Number.isSafeInteger(n)&&n>=100&&n<=1000000);
}
export function validateProduct(value){
 if(!value||!PRODUCT_IDS.includes(value.id)||typeof value.enabled!=='boolean')fail('INVALID_PRODUCT');
 const prices=value.prices;
 if(!validPrices(prices))fail('INVALID_PRICE');
 const bundles=value.bundles??{};
 if(value.id==='analysis-credits'){
   if(!bundles||typeof bundles!=='object'||Array.isArray(bundles)||
     Object.keys(bundles).some(k=>!Object.hasOwn(CREDIT_PACKS,k)||!validPrices(bundles[k])))fail('INVALID_PRICE');
   if(value.enabled&&!Object.values(bundles).some(p=>Object.keys(p).length))fail('PRICE_REQUIRED');
   return {id:value.id,enabled:value.enabled,prices:{},bundles,
     quota:null,days:null,maxDevices:null};
 }
 const termPrices=value.termPrices??{};
 if(!termPrices||typeof termPrices!=='object'||Array.isArray(termPrices)||
   Object.keys(termPrices).some(k=>!Object.hasOwn(TERMS,k)||!validPrices(termPrices[k])))fail('INVALID_PRICE');
 if(value.enabled&&!Object.keys(prices).length&&!Object.values(termPrices).some(p=>Object.keys(p).length))fail('PRICE_REQUIRED');
 if(value.id==='api-ip'&&(!Number.isInteger(value.quota)||value.quota<1||value.quota>1000000||
   !Number.isInteger(value.days)||value.days<1||value.days>3650))fail('INVALID_API_PLAN');
 return {id:value.id,enabled:value.enabled,prices,termPrices,
   quota:value.id==='api-ip'?value.quota:null,days:value.id==='api-ip'?value.days:null,
   maxDevices:value.id==='offline-3'?3:null};
}
export function planFor(product,term='base'){
 if(product.id==='analysis-credits'){
   if(!Object.hasOwn(CREDIT_PACKS,term))fail('INVALID_TERM');
   return {id:term,credits:CREDIT_PACKS[term],days:null,prices:product.bundles?.[term]||{}};
 }
 if(term==='base')return {id:'base',days:product.days??null,prices:product.prices||{}};
 if(!Object.hasOwn(TERMS,term))fail('INVALID_TERM');
 return {id:term,days:TERMS[term]*30,prices:product.termPrices?.[term]||{}};
}
export function plansFor(product){
 if(product.id==='analysis-credits')return Object.keys(CREDIT_PACKS).map(id=>planFor(product,id));
 const base=planFor(product);
 return [{...base,title:product.id==='offline-3'?'lifetime':'custom'},...Object.keys(TERMS).map(id=>planFor(product,id))];
}
export function productAvailable(product,env=process.env){
 return product.enabled&&env.SPDECODE_STORE_ENABLED==='true'&&
   (product.id==='api-ip'?env.SPDECODE_COMMERCIAL_API_ENABLED==='true':
    product.id==='analysis-credits'?env.SPDECODE_ANALYSIS_CREDITS_READY==='true':
    env.SPDECODE_OFFLINE_LICENSE_READY==='true');
}
export function planAvailable(product,term,env=process.env){
 return productAvailable(product,env)&&
   !(product.id==='offline-3'&&term!=='base'&&env.SPDECODE_OFFLINE_TIMED_LICENSE_READY!=='true');
}
export function publicProduct(row,env=process.env){
 const data=typeof row.settings==='string'?JSON.parse(row.settings):row.settings;
 const providers=['stripe','paypal','mercadopago'].filter(id=>paymentReady(id,env));
 return {...data,plans:plansFor(data).map(p=>({...p,available:planAvailable(data,p.id,env)&&providers.length>0})),
   version:row.version,available:productAvailable(data,env)&&providers.length>0,providers};
}
export function taxQuote(product,currency,country,region,rules,term='base'){
 if(!/^[A-Z]{2}$/.test(country)||typeof region!=='string'||!/^[A-Z0-9-]{0,12}$/.test(region))fail('INVALID_LOCATION');
 const plan=planFor(product,term),subtotal=plan.prices[currency];
 if(!subtotal)fail('CURRENCY_UNAVAILABLE');
 const rule=rules.find(r=>r.country===country&&r.region===region)||rules.find(r=>r.country===country&&r.region==='*');
 if(!rule||!rule.reviewed||!Number.isInteger(rule.rateBps)||rule.rateBps<0||rule.rateBps>3000)fail('TAX_NOT_CONFIGURED',409);
 const tax=Math.round(subtotal*rule.rateBps/10000);
 return {currency,subtotal,tax,total:subtotal+tax,country,region,taxLabel:rule.label||'Tax',taxRateBps:rule.rateBps,
   ...(rule.stripeTaxRate?{stripeTaxRate:rule.stripeTaxRate}:{})};
}
export function validatePurchase(body){
 if(!body||!PRODUCT_IDS.includes(body.product)||!['stripe','paypal','mercadopago'].includes(body.provider)||
   !CURRENCIES.includes(body.currency)||!Number.isSafeInteger(body.version)||
   !/^[0-9a-f-]{36}$/.test(body.idempotencyKey||'')||body.acceptedTerms!=='2026-11-10'||
   (body.product==='analysis-credits'
     ?!Object.hasOwn(CREDIT_PACKS,body.term)
     :(body.term!==undefined&&body.term!=='base'&&!Object.hasOwn(TERMS,body.term))))fail('INVALID_REQUEST');
 // An API license may be purchased before the owner provisions a VPS.
 // The API key cannot be claimed or used until a public IP is bound.
 const ip=body.product==='api-ip' && body.allowedIp!==undefined &&
   body.allowedIp!==null && body.allowedIp!==''?publicIp(body.allowedIp):null;
 if(body.product==='api-ip' && body.allowedIp!=null && body.allowedIp!=='' && !ip)
   fail('INVALID_PUBLIC_IP');
 if(body.provider==='mercadopago'&&body.currency!=='MXN')fail('CURRENCY_UNAVAILABLE');
 return {...body,term:body.term||(body.product==='analysis-credits'?null:'base'),allowedIp:ip};
}
