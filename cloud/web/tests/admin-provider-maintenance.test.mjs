import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const read=path=>readFileSync(new URL("../"+path,import.meta.url),"utf8");

test("the provider list exposes independent visible maintenance and administrative availability switches",()=>{
 const view=read("app/admin/admin-dashboard.jsx");
 assert.match(view,/visibleProviders\.map\(provider=>/);
 assert.match(view,/methodsById\[provider\.id\]/);
 assert.match(view,/disabledProviderIds\.includes\(provider\.id\)/);
 assert.match(view,/>Mantenimiento<\/span>/);
 assert.match(view,/onClick=\{\(\)=>changeMethodStatus\(provider\.id,"maintenance",!method\.maintenance,provider\.name\)\}/);
 assert.match(view,/onClick=\{\(\)=>changeProvider\(provider\.id,!manuallyEnabled,provider\.name\)\}/);
 assert.match(view,/<option value="maintenance">En mantenimiento<\/option>/);
 assert.match(view,/method\?\.maintenance\?"En mantenimiento/);
 assert.match(view,/aria-checked=\{manuallyEnabled\}/);
});

test("maintenance page lists individual catalog statuses without disabling the whole VPN service",()=>{
 const view=read("app/admin/admin-dashboard.jsx");
 assert.match(view,/mode==="maintenance"/);
 assert.match(view,/Mantenimiento por catálogo Server VPN/);
 assert.match(view,/visibleMethods\.map\(method=>/);
 assert.match(view,/onClick=\{\(\)=>changeMethodStatus\(method\.id,"maintenance",!method\.maintenance,method\.name\)\}/);
 assert.match(view,/En mantenimiento: \{methodStatuses\.filter\(m=>m\.maintenance\)\.length\}/);
 const api=read("lib/c6-admin-api.mjs");
 assert.match(api,/providerMethodRequest/);
 assert.match(api,/updateMethodState\(body\.id,body\.operation,body\.maintenance\)/);
 const state=read("lib/c12-provider-controls.mjs");
 assert.match(state,/disabledProviderIds:\[\.\.\.state\.disabled\]/);
 assert.match(state,/disabledProviderIds:\[\.\.\.updated\.disabled\]/);
 assert.match(state,/disabledProviderIds:\[\.\.\.next\.disabled\]/);
 assert.match(state,/!methodMaintenance\(state,id\)/);
 const css=read("app/admin/admin-theme.css");
 assert.match(css,/sp-admin-catalog-actions/);
});
