import test from "node:test";
import assert from "node:assert/strict";
import dns from "node:dns/promises";
import https from "node:https";
import {EventEmitter} from "node:events";
import {downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";

function enable(t) {
  const previous=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.CLOUD_SERVER_VPN_ENABLED="true";
  t.after(()=>{
    if(previous===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;
    else process.env.CLOUD_SERVER_VPN_ENABLED=previous;
  });
}

test("Jireh refuses even same-origin Dropbox redirects without falling back to stale GitHub",async t=>{
  enable(t);
  let calls=0;
  t.mock.method(dns,"lookup",async host=>{
    assert.equal(host,"dl.dropboxusercontent.com");
    return [{address:"93.184.216.34",family:4}];
  });
  t.mock.method(https,"request",(url,_options,callback)=>{
    calls++;
    assert.equal(url.pathname,"/scl/fi/9p6vvoa8jfch3ribneckq/HTTPJIREH1117");
    const request=new EventEmitter();request.destroy=()=>{};
    request.end=()=>queueMicrotask(()=>{
      const response=new EventEmitter();response.resume=()=>{};
      response.statusCode=302;
      response.headers={location:`https://${url.host}/different-catalog${url.search}`};
      callback(response);
    });
    return request;
  });
  await assert.rejects(()=>downloadVpnCatalog("http-jireh"),{code:"REMOTE_NETWORK_DENIED"});
  assert.equal(calls,1);
});

test("Jireh keeps Cloud server-only, accepts no custom URL and respects the deployment switch",async t=>{
  enable(t);
  t.mock.method(dns,"lookup",()=>{throw Error("unexpected network");});
  for(const source of ["users","https://attacker.invalid/","../NETWORK2"])
    await assert.rejects(()=>downloadVpnCatalog("http-jireh",source),{code:"UNSUPPORTED_FORMAT"});
  process.env.CLOUD_SERVER_VPN_ENABLED="false";
  await assert.rejects(()=>downloadVpnCatalog("http-jireh"),{code:"REMOTE_NOT_CONFIGURED"});
});
