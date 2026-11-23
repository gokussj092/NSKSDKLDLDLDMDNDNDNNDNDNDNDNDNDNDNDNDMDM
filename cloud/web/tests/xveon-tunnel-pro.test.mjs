import test from "node:test";
import assert from "node:assert/strict";
import {publicFormats} from "../lib/file-format-catalog.mjs";
import {publicTextFormats} from "../lib/text-format-catalog.mjs";
import {catalog} from "../lib/server-vpn-catalog.mjs";
import {SUPPLIED_INTEGRATIONS} from "../lib/supplied-integrations.mjs";

// XVEON Tunnel Pro 8.1 (com.xveon.tunnelpro, code 8): FILE_ONLY, no
// catalog, no provider card. Files .xveon/.xvn + texts xveontunnel://,
// xveon://, xvn:// via decoders/Python/apps/XVEON_Tunnel_Pro.

test("XVEON Tunnel Pro publishes .xveon/.xvn file routes",()=>{
  const formats=publicFormats();
  assert.deepEqual(formats.find(x=>x.suffix==="xveon"),{
    suffix:"xveon",name:"XVEON Tunnel Pro 8.1",kind:"file",
    offlineSupported:false,cloudSupported:true,credentialFields:["password"],
  });
  assert.deepEqual(formats.find(x=>x.suffix==="xvn"),{
    suffix:"xvn",name:"XVEON Tunnel Pro 8.1",kind:"file",
    offlineSupported:false,cloudSupported:true,credentialFields:["password"],
  });
  assert.equal(new Set(formats.map(x=>x.suffix)).size,formats.length);
});

test("XVEON Tunnel Pro publishes its three text schemes",()=>{
  const formats=publicTextFormats();
  for(const prefix of ["xveontunnel://","xveon://","xvn://"]){
    assert.deepEqual(formats.find(x=>x.prefix===prefix),{
      prefix,name:"XVEON Tunnel Pro",suffix:"xveon",kind:"text",
    });
  }
  assert.equal(new Set(formats.map(x=>x.prefix.toLowerCase())).size,
    formats.length);
});

test("XVEON Tunnel Pro has a FILE_ONLY supplied entry and no catalog card",()=>{
  const item=SUPPLIED_INTEGRATIONS.find(x=>x.id==="xveon-tunnel-pro");
  assert.equal(item.appDir,"XVEON_Tunnel_Pro");
  assert.equal(item.package,"com.xveon.tunnelpro");
  assert.equal(item.versionCode,8);
  assert.equal(item.versionName,"8.1");
  assert.deepEqual(item.extensions,["xveon","xvn"]);
  assert.deepEqual(item.textPrefixes,
    ["xveontunnel://","xveon://","xvn://"]);
  assert.equal(item.fileModule,"file_decoder.py");
  assert.deepEqual(item.requests,[]);
  assert.equal(item.icon,"xveon-tunnel-pro.png");
  assert.equal(item.catalogState,"FILE_ONLY");
  const result=catalog();
  assert.equal(result.formatCount,publicFormats().length);
  assert.equal(result.textCount,publicTextFormats().length);
  assert(!result.apps.some(x=>x.id==="xveon-tunnel-pro"));
  const payload=JSON.stringify(result);
  for(const forbidden of [
    "decoders/Python/",'"script":',"source_script","originalRuntime",
    "migrationPhase","androidPortStatus","__proto__","privateKey",
  ]) assert(!payload.includes(forbidden),forbidden);
});
