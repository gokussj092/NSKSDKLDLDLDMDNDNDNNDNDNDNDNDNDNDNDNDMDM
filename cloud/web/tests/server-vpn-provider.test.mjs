import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

for(const provider of [
  {id:"tunneltweak",host:"tunneltweak.com",path:"/api/servers",query:"",agent:"TunnelTweak/1.0 (Android)",headers:{"ngrok-skip-browser-warning":"true","x-app-version":"51","x-cfg-keyed":"1"}},
  {id:"http-jireh",host:"raw.githubusercontent.com",path:"/alvarofelizzola/GEN-JIREH/refs/heads/main/GENERADOR",query:"",agent:"HTTP Jireh/2.0"},
  {id:"http-fenixvpn",host:"raw.githubusercontent.com",path:"/Fenix1998x/GEN-SERVIDORES-NUEVO-24-08-2027/refs/heads/main/Fenix",query:"",agent:"HTTP FenixVPN/19.4"},
  {id:"austroplus-vpn",host:"raw.githubusercontent.com",path:"/SpkHexX/HexX/refs/heads/main/AustroPlusVPN.json",query:"",agent:"AustroPlus VPN/13.0.1"},
  {id:"ac-tunnel-vpn",host:"rttunnelv2ray.xyz",path:"/api/files/app",query:"?json=7ef7a9a142eb1f77a56f",agent:"AC TUNNEL VPN/1.4"},
  {id:"my-tunnel-proxy",host:"mfmpro.xyz",path:"/api/app",query:"?json=3c9a2a29f3a4180271da",agent:"My Tunnel Proxy/2.3"},
  {id:"robust-tunnel",host:"xkingvpn.xyz",path:"/api/files/app",query:"?json=beae113e6e46d674a068",agent:"Robust Tunnel VPN/isvsoft 16.4.7"},
  {id:"trv-tunnel",host:"trmrelay.store",path:"/updater/b67b57c85f49c34ee09fd87f2d6915",query:"",agent:"TRV TUNNEL/2.4"},
  {id:"4u-tunnel-lite",host:"ctxrelay.online",path:"/updater/08f9aa63574a055cffdac66783b05b",query:"",agent:"4U TUNNEL LITE/2.2"},
]) test(`${provider.id} fixed endpoint is pinned across DNS, TLS and redirects`,async t=>{
  const prior=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{
    if(prior===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;
    else process.env.CLOUD_SERVER_VPN_ENABLED=prior;
  });
  let dnsAddress="93.184.216.34",mode="success",calls=0;
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,provider.host);
    return [{address:dnsAddress,family:4}];
  });
  t.mock.method(https,"request",(url,options,callback)=>{
    calls++;
    assert.equal(url.hostname,provider.host);
    assert.equal(url.pathname,provider.path);
    assert.equal(url.search,provider.query);
    assert.equal(options.rejectUnauthorized,true);
    assert.equal(options.minVersion,"TLSv1.2");
    assert.equal(options.headers["User-Agent"],provider.agent);
    for(const [key,value] of Object.entries(provider.headers||{}))assert.equal(options.headers[key],value);
    assert.equal(options.headers["x-api-key"],undefined);
    options.lookup(provider.host,{},(error,ip,family)=>{
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
  assert.equal((await downloadVpnCatalog(provider.id)).toString(),"fixed catalog bytes");
  for(const redirect of [
    `https://${provider.host}${provider.path}?json=changed`,
    ...(provider.query ? [`https://${provider.host}${provider.path}`] : []),
    `https://other.invalid${provider.path}${provider.query}`,
    `http://${provider.host}${provider.path}${provider.query}`,
  ]){
    mode=redirect;
    await assert.rejects(()=>downloadVpnCatalog(provider.id),{code:"REMOTE_NETWORK_DENIED"});
  }
  const before=calls;dnsAddress="127.0.0.1";
  await assert.rejects(()=>downloadVpnCatalog(provider.id),{code:"REMOTE_NETWORK_DENIED"});
  assert.equal(calls,before);
});
