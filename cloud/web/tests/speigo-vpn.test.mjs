import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {createHash} from "node:crypto";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {catalog,iconFor,CATALOG_VERSION} from "../lib/server-vpn-catalog.mjs";
import {providerIds,downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";
const v=JSON.parse(readFileSync(new URL("../../../analysis/netfree.mx.speigovpn/159/tests/fixtures/vectors.json",import.meta.url),"utf8"));
const ids=["speigo-vpn-configs","speigo-vpn-ssh"];
const paths=["/apksdemons/apks2/refs/heads/main/speigo/servr_speigosx_sv5c","/apksdemons/apks2/refs/heads/main/speigo/user_speigo_sv5c"];
const bodies=[Buffer.from(v.configs,"base64"),Buffer.from(v.ssh,"base64")];
function enabled(t){const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});}
test("SpeiGo configurations and SSH are distinct public entries with the exact original icon",t=>{
 enabled(t);const doc=catalog();assert.ok(CATALOG_VERSION>=78);assert.ok(doc.apps.length>=71);
 for(const id of ids){const a=doc.apps.find(a=>a.id===id);assert(a);assert.equal(a.decodeEnabled,true);assert(providerIds().includes(id));assert(PUBLIC_PROVIDER_IDS.includes(id));assert(!JSON.stringify(a).includes("apksdemons"));const icon=iconFor(id);assert.equal(createHash("sha256").update(icon.bytes).digest("hex"),"09acd58c6af0d0892530574cd33e3d417ed1743bea741337de33f56b87dc6581");}
 assert(!providerIds().includes("speigo-vpn"));assert.notEqual(doc.apps.find(a=>a.id===ids[0]).name,doc.apps.find(a=>a.id===ids[1]).name);
});
test("each source downloads independently and keeps DNS/TLS/redirect restrictions",async t=>{
 enabled(t);let address="93.184.216.34",redirect=null,configDown=false;const calls=[];
 t.mock.method(dns,"lookup",async h=>{assert.equal(h,"raw.githubusercontent.com");return [{address,family:4}];});
 t.mock.method(https,"request",(url,opts,callback)=>{
  const index=paths.indexOf(url.pathname);assert(index>=0);calls.push(index);assert.equal(opts.rejectUnauthorized,true);assert.equal(opts.minVersion,"TLSv1.2");assert.equal(opts.headers.Accept,"application/octet-stream");assert.equal(opts.headers["Accept-Encoding"],"identity");
  const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.resume=()=>{};res.statusCode=redirect?302:configDown&&index===0?503:200;res.headers=redirect?{location:redirect}:{};callback(res);if(res.statusCode===200){res.emit("data",bodies[index]);res.emit("end");}});return req;
 });
 for(let i=0;i<2;i++){const n=calls.length;assert.deepEqual(await downloadVpnCatalog(ids[i]),bodies[i]);assert.deepEqual(calls.slice(n),[i]);}
 redirect="https://raw.githubusercontent.com"+paths[1];await assert.rejects(()=>downloadVpnCatalog(ids[0]),{code:"REMOTE_NETWORK_DENIED"});redirect=null;
 configDown=true;await assert.rejects(()=>downloadVpnCatalog(ids[0]),{code:"REMOTE_PROVIDER_UNAVAILABLE"});assert.deepEqual(await downloadVpnCatalog(ids[1]),bodies[1]);
 address="127.0.0.1";const n=calls.length;await assert.rejects(()=>downloadVpnCatalog(ids[1]),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls.length,n);
});
test("operator switches and maintenance control the two SpeiGo entries independently",t=>{
 enabled(t);
 for(const state of [{availability:{[ids[0]]:false}},{methodStates:{[ids[0]]:{maintenance:true}}}]){const list=catalog(state).apps;assert.equal(list.find(a=>a.id===ids[0]).decodeEnabled,false);assert.equal(list.find(a=>a.id===ids[1]).decodeEnabled,true);}
});
