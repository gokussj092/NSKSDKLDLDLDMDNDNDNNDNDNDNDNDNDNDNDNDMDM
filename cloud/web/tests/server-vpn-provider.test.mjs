import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

test("My Tunnel fixed query is pinned across DNS, TLS and redirects",async t=>{
  const prior=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{
    if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;
    else process.env.CLOUD_SERVER_VPN_ENABLED=prior;
  });
  let dnsAddress="93.184.216.34",mode="success",calls=0;
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"mfmpro.xyz");
    return [{address:dnsAddress,family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    calls++;
    assert.equal(url.hostname,"mfmpro.xyz");
    assert.equal(url.search,"?json=3c9a2a29f3a4180271da");
    assert.equal(options.rejectUnauthorized,true);
    assert.equal(options.minVersion,"TLSv1.2");
    assert.equal(options.headers["User-Agent"],"My Tunnel Proxy/2.3");
    options.lookup("mfmpro.xyz",{},(error,ip,family)=>{
      assert.equal(error,null);assert.equal(ip,dnsAddress);assert.equal(family,4);
    });
    const request=new EventEmitter();
    request.destroy=()=>{};
    request.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=mode==="success"?200:302;
      response.headers=mode==="success"?{}:{location:mode};
      callback(response);
      if(mode==="success"){
        response.emit("data",Buffer.from("fixed catalog bytes"));response.emit("end");
      }
    });
    return request;
  });
  assert.equal((await downloadVpnCatalog("my-tunnel-proxy")).toString(),"fixed catalog bytes");
  for(const redirect of [
    "https://mfmpro.xyz/api/app?json=changed",
    "https://mfmpro.xyz/api/app",
    "https://other.invalid/api/app?json=3c9a2a29f3a4180271da",
    "http://mfmpro.xyz/api/app?json=3c9a2a29f3a4180271da",
  ]){
    mode=redirect;
    await assert.rejects(()=>downloadVpnCatalog("my-tunnel-proxy"),{code:"REMOTE_NETWORK_DENIED"});
  }
  const before=calls;dnsAddress="127.0.0.1";
  await assert.rejects(()=>downloadVpnCatalog("my-tunnel-proxy"),{code:"REMOTE_NETWORK_DENIED"});
  assert.equal(calls,before);
});
