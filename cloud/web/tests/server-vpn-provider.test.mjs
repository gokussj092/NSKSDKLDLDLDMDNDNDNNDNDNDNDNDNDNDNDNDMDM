import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog,mkkSourceIds} from "../lib/server-vpn-provider.mjs";
import {packMkkSources} from "../lib/mkk-source-bundle.mjs";

for(const provider of [
  {id:"bd-net-vpn",host:"raw.githubusercontent.com",path:"/panigbatanc/BDNET2023/main/JSONDEC2025",query:"",agent:"BD NET VPN/PrinceBuild111"},
  {id:"aura-net-vpn",host:"strongteam.co",path:"/api/kidvpn/v4/aurav1.txt",query:"",agent:"Aura Net VPN"},
  {id:"apna-vpn",host:"paperonboard.com",path:"/updater/3c3c4c58d864ca394da16656b4d0c4",query:"",agent:"Dalvik/2.1.0"},
  {id:"any-vpn",host:"free-panel.myprotectionservices.com",path:"/uploads/json/1e760370dff563b8fa00.json",query:"",agent:"okhttp/5.0.0-alpha.12"},
  {id:"speicers-pro-vpn",host:"raw.githubusercontent.com",path:"/satanas66666/Aplicaciones/refs/heads/main/speicerspro/servidores_pro",query:"",agent:"Speicers Pro/104.1.17"},
  {id:"tx-tunnel",host:"strongteam.co",path:"/api/txtunnel/v1/",query:"?appcode=27.0",agent:"Tx Tunnel"},
  {id:"abowaged-vpn",host:"raw.githubusercontent.com",path:"/th3fre/Testing/refs/heads/main/Elk.txt",query:"",agent:"AboWaged VPN/1.0"},
  {id:"http-socketclay",host:"dl.dropboxusercontent.com",path:"/scl/fi/vh319xyu0ck84ks0wdqw8/ServersSC",query:"?rlkey=b9g57byy0igz2jitqix31t4i4&st=evmzpf11&dl=1",agent:"HTTP SocketClay/3.4.0"},
  {id:"tunneltweak",host:"tunneltweak.com",path:"/api/servers",query:"",agent:"TunnelTweak/1.0 (Android)",headers:{"ngrok-skip-browser-warning":"true","x-app-version":"51","x-cfg-keyed":"1"}},
  {id:"http-jireh",host:"raw.githubusercontent.com",path:"/alvarofelizzola/GEN-JIREH/refs/heads/main/GENERADOR",query:"",agent:"HTTP Jireh/2.0"},
  {id:"http-fenixvpn",host:"raw.githubusercontent.com",path:"/Fenix1998x/GEN-SERVIDORES-NUEVO-24-08-2027/refs/heads/main/Fenix",query:"",agent:"HTTP FenixVPN/19.4"},
  {id:"austroplus-vpn",host:"raw.githubusercontent.com",path:"/SpkHexX/HexX/refs/heads/main/AustroPlusVPN.json",query:"",agent:"AustroPlus VPN/13.0.1"},
  {id:"ac-tunnel-vpn",host:"rttunnelv2ray.xyz",path:"/api/files/app",query:"?json=7ef7a9a142eb1f77a56f",agent:"AC TUNNEL VPN/1.4"},
  {id:"ksh-vpn",host:"raw.githubusercontent.com",path:"/yannaing86tt/ksh_server/main/servers.json",query:"",agent:"KSH VPN/1.3.2"},
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

test("MKK four approved catalog sources are individually bound to fixed HTTPS endpoints",async t=>{
 const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;});
 const approved={
  servers:["f005.backblazeb2.com","/file/mkkhyper/api_server.json"],
  static:["flashvpn.sgp1.digitaloceanspaces.com","/static.json"],
  subscriptions:["f005.backblazeb2.com","/file/mkkhyper/subscriptions.json"],
  "legacy-subscriptions":["raw.githubusercontent.com","/Tunzen665/flash-vpn/refs/heads/main/sub.json"],
 };
 assert.deepEqual(mkkSourceIds(),Object.keys(approved));
 let current="";
 t.mock.method(dns,"lookup",async host=>{
  assert.equal(host,approved[current][0]);
  return [{address:"93.184.216.34",family:4}];
 });
 t.mock.method(https,"request",(url,options,callback)=>{
  assert.equal(url.hostname,approved[current][0]);
  assert.equal(url.pathname,approved[current][1]);
  assert.equal(options.headers["User-Agent"],"MKK Hyper VPN/2.9.2");
  const req=new EventEmitter();req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{
   const res=new EventEmitter();res.resume=()=>{};
   res.statusCode=200;res.headers={};
   callback(res);res.emit("data",Buffer.from(current));res.emit("end");
  });
  return req;
 });
 for(const id of mkkSourceIds()){
  current=id;
  assert.equal((await downloadVpnCatalog("mkk-hyper",id)).toString(),id);
 }
 await assert.rejects(()=>downloadVpnCatalog("mkk-hyper","https://evil.invalid"),{code:"UNSUPPORTED_FORMAT"});
 await assert.rejects(()=>downloadVpnCatalog("ksh-vpn","subscriptions"),{code:"UNSUPPORTED_FORMAT"});
});

test("MKK intermittent HTTP 503 recovers with one bounded retry on same public IP",async t=>{
 const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
 process.env.CLOUD_SERVER_VPN_ENABLED="true";
 t.after(()=>{if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;else process.env.CLOUD_SERVER_VPN_ENABLED=previous;});
 let count=0;
 t.mock.method(dns,"lookup",async()=>[{address:"93.184.216.34",family:4}]);
 t.mock.method(https,"request",(_url,options,callback)=>{
  assert.equal(options.rejectUnauthorized,true);
  const req=new EventEmitter();
  req.destroy=()=>{};
  req.end=()=>queueMicrotask(()=>{
   count++;
   const res=new EventEmitter();res.resume=()=>{};
   res.statusCode=count===1?503:200;res.headers={};
   callback(res);
   if(count>1){res.emit("data",Buffer.from("valid MKK bytes"));res.emit("end");}
  });
  return req;
 });
 assert.equal((await downloadVpnCatalog("mkk-hyper","servers")).toString(),"valid MKK bytes");
 assert.equal(count,2);
});
test("MKK budget preserves complete approved sources and marks omissions explicitly",()=>{
 const sources=[
  {name:"servers",status:"ok",dataBase64:"A".repeat(600)},
  {name:"static",status:"ok",dataBase64:"B".repeat(600)},
  {name:"subscriptions",status:"error",error:"REMOTE_PROVIDER_UNAVAILABLE"},
  {name:"legacy-subscriptions",status:"error",error:"REMOTE_PROVIDER_UNAVAILABLE"},
 ];
 const selected=packMkkSources(sources,1050);
 const body=JSON.parse(selected.payload.toString("utf8"));
 assert.equal(body.kind,"spdecode-mkk-sources-v1");
 assert.ok(selected.payload.length<=1050);
 assert.equal(body.sources.length,4);
 assert.deepEqual(body.sources.map(x=>x.name),mkkSourceIds());
 assert.equal(body.sources[0].status,"ok");
 assert.equal(body.sources[0].dataBase64,sources[0].dataBase64);
 assert.deepEqual(body.sources[1],{name:"static",status:"error",error:"REMOTE_TOO_LARGE"});
 assert.equal(body.sources[2].error,"REMOTE_PROVIDER_UNAVAILABLE");
 assert.equal(sources[1].status,"ok"); // no mutation or truncation
});
