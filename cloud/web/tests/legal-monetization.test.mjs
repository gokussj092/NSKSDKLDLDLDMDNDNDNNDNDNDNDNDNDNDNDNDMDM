import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const legal=readFileSync(new URL("../app/public/legal.jsx",import.meta.url),"utf8");
const terms=readFileSync(new URL("../app/terms/page.jsx",import.meta.url),"utf8");
const privacy=readFileSync(new URL("../app/privacy/page.jsx",import.meta.url),"utf8");
const support=readFileSync(new URL("../app/support/page.jsx",import.meta.url),"utf8");
const manifest=readFileSync(new URL("../../../android/app/src/main/AndroidManifest.xml",import.meta.url),"utf8");
const gradle=readFileSync(new URL("../../../android/app/build.gradle.kts",import.meta.url),"utf8");
const webPackage=JSON.parse(readFileSync(new URL("../package.json",import.meta.url),"utf8"));

test("public legal pages reflect current features, with no draft, advertising or subscription claims",()=>{
 const prohibited=/\b(?:draft|provisional|advertis(?:e|ing|ement|ements)|subscriptions?|billing|admob)\b|borrador|provisional|anuncios|publicidad|suscripci[oó]n|monetizaci[oó]n|renovaci[oó]n autom[aá]tica/i;
 assert.doesNotMatch(legal,prohibited);
 assert.doesNotMatch(terms,/provisional|borrador/i);
 assert.doesNotMatch(legal,/play\.google\.com\/store\/account\/subscriptions/);
 assert.doesNotMatch(legal,/<a[^>]+play\.google\.com\/store\/account/);
 assert.match(legal,/25 de octubre de 2026/);
 assert.match(legal,/October 25, 2026/);
});

test("terms, privacy and support are served under existing bilingual routes",()=>{
 assert.match(terms,/PublicLegal kind="terms"/);
 assert.match(privacy,/PublicLegal kind="privacy"/);
 assert.match(support,/PublicLegal kind="support"/);
 for(const label of [
  "Términos y condiciones de uso de SP-DECODE",
  "SP-DECODE Terms and Conditions of Use",
  "Política de privacidad de SP-DECODE",
  "SP-DECODE Privacy Policy",
  "Soporte técnico de SP-DECODE",
  "SP-DECODE Technical Support",
  "soporte@spdecode.xyz"
 ])assert.ok(legal.includes(label),label);
 assert.match(legal,/usePublicLocale/);
 assert.match(legal,/sp-legal-card/);
});

test("permissions and HWID explanation match main Android manifest",()=>{
 const permissions=[...manifest.matchAll(/<uses-permission\s+android:name="([^"]+)"/g)].map(x=>x[1]);
 assert.deepEqual(permissions,["android.permission.INTERNET"]);
 assert.match(legal,/IMEI/);
 assert.match(legal,/Android ID/);
 assert.match(legal,/HWID/);
 assert.match(legal,/no lee el IMEI/);
 assert.match(legal,/does not directly obtain IMEI/);
});

test("privacy documents existing Cloud data flow, storage, keys and operational retention",()=>{
 for(const term of [
  "HTTPS","AES-256-GCM","Android Keystore",
  "Google Play Integrity","HyperLogLog","HMAC",
  "8 días","32 días","8 days","32 days",
  "clave privada","private key",
  "identificador hash","IP-derived hash",
  "7, 30, 90 o 365 días","7, 30, 90 or 365 days",
  "permisos de ubicación","location, contacts, camera",
  "consentimiento","consent",
  "local storage","almacenamiento local"
 ])assert.ok(legal.includes(term),term);
 assert.match(gradle,/com\.google\.android\.play:integrity/);
 assert.doesNotMatch(gradle,/com\.google\.android\.gms:play-services-ads|com\.android\.billingclient:billing/);
});

test("support discourages sharing secrets and explains optional NPV identity use",()=>{
 for(const term of [
  "nunca envíes claves privadas","never send private keys",
  "identidades NPV","NPV identities",
  "Reportar un problema","Reporting a problem",
  "contraseña incorrecta","incorrect password",
  "historial","history"
 ])assert.ok(legal.includes(term),term);
 assert.equal(webPackage.scripts.test,"node --test tests/*.test.mjs");
});
