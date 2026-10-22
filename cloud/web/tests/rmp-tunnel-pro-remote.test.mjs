import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

function setup(t,{address="93.184.216.34",redirect=false}={}){
 const old=process.env.CLOUD_SERVER_VPN_ENABLED;process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(old===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=old;});
 t.mock.method(dns,"lookup",async host=>{assert.equal(host,"raw.githubusercontent.com");return [{address,family:4}];});
 let calls=0;
 t.mock.method(https,"request",(url,options,callback)=>{
  calls++;assert.equal(url.href,"https://raw.githubusercontent.com/pipoyrichards/RMPSYSTEM/refs/heads/main/RMPPRO");
  assert.equal(options.rejectUnauthorized,true);assert.equal(options.minVersion,"TLSv1.2");
  options.lookup(url.hostname,{},(err,ip,family)=>{assert.equal(err,null);assert.equal(ip,address);assert.equal(family,4);});
  const request=new EventEmitter();request.destroy=()=>{};
  request.end=()=>queueMicrotask(()=>{const response=new EventEmitter();response.resume=()=>{};
   response.statusCode=redirect?302:200;response.headers=redirect?{location:"https://raw.githubusercontent.com/other/file"}:{};
   callback(response);if(!redirect){response.emit("data",Buffer.from("complete-source"));response.emit("end");}
  });return request;
 });return ()=>calls;
}
test("RMP TUNNEL PRO uses its exact fixed HTTPS source and public pinned DNS",async t=>{
 const calls=setup(t);assert.equal((await downloadVpnCatalog("rmp-tunnel-pro")).toString(),"complete-source");assert.equal(calls(),1);
 await assert.rejects(()=>downloadVpnCatalog("rmp-tunnel-pro","https://evil.invalid"),{code:"UNSUPPORTED_FORMAT"});
});
test("RMP TUNNEL PRO rejects private DNS before transport",async t=>{
 const calls=setup(t,{address:"127.0.0.1"});await assert.rejects(()=>downloadVpnCatalog("rmp-tunnel-pro"),{code:"REMOTE_NETWORK_DENIED"});assert.equal(calls(),0);
});
test("RMP TUNNEL PRO refuses same-origin redirects",async t=>{
 setup(t,{redirect:true});await assert.rejects(()=>downloadVpnCatalog("rmp-tunnel-pro"),{code:"REMOTE_NETWORK_DENIED"});
});
