import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const legal=readFileSync(new URL("../app/public/legal.jsx",import.meta.url),"utf8");
const terms=readFileSync(new URL("../app/terms/page.jsx",import.meta.url),"utf8");
const privacy=readFileSync(new URL("../app/privacy/page.jsx",import.meta.url),"utf8");
const webPackage=JSON.parse(readFileSync(new URL("../package.json",import.meta.url),"utf8"));
test("future ads and subscriptions are explicitly not represented as already active, ES/EN",()=>{
 for(const term of [
   "están planificadas, pero no están activas",
   "are planned but are not enabled",
   "La compra aún no está disponible",
   "Purchases are not currently available",
   "19 de octubre de 2026",
   "October 19, 2026"
 ])assert.ok(legal.includes(term),term);
});
test("terms cover monthly recurrence, transparent checkout, cancellation, refunds and mandatory consumer rights",()=>{
 for(const term of [
   "renovación automática","Google Play","Desinstalar la aplicación no cancela",
   "reembolso","mandatory consumer rights","automatic renewal",
   "Uninstalling the app does not cancel"
 ])assert.ok(legal.includes(term),term);
 assert.ok(legal.includes("https://play.google.com/store/account/subscriptions"));
});
test("privacy covers potential advertising IDs, third parties, billing entitlements and rights without invented vendors",()=>{
 for(const term of [
   "identificadores publicitarios","dirección IP","SDK","token o identificador de compra",
   "soporte@spdecode.xyz","advertising identifier","billing","enabling advertising",
   "Google Play Data safety"
 ])assert.ok(legal.includes(term),term);
 assert.ok(!/AdMob|Meta Audience Network|Unity Ads/.test(legal),"A provider must only be named once actually integrated");
});
test("unchanged Cloud notice and protected legal routing stay available",()=>{
 assert.match(legal,/AES-256-GCM/);
 assert.match(legal,/Android Keystore/);
 assert.match(legal,/Configuraciones propias|configuraciones propias/);
 assert.match(terms,/PublicLegal kind="terms"/);
 assert.match(privacy,/PublicLegal kind="privacy"/);
 assert.equal(webPackage.scripts.test,"node --test tests/*.test.mjs");
});
