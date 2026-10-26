import test from "node:test";
import assert from "node:assert/strict";
import {catalog, iconFor, CATALOG_VERSION, activeCatalogVersion} from "../lib/server-vpn-catalog.mjs";
import {providerIds, providerEnabled, downloadVpnCatalog} from "../lib/server-vpn-provider.mjs";
import {PUBLIC_PROVIDER_IDS} from "../lib/c12-provider-controls.mjs";

test("TunnelDOOM original launcher PNG and disabled card survive global enablement",()=>{
  const doc=catalog({availability:{"tunneldoom-vpn":true}});
  assert.equal(CATALOG_VERSION,55);
  assert.equal(doc.apps.length,49);
  const app=doc.apps.find(x=>x.id==="tunneldoom-vpn");
  assert.equal(app.name,"TunnelDOOM VPN");
  assert.equal(app.decodeEnabled,false);
  assert.equal(app.iconSha256,"ce33bc4ef6b663f43af31dc72bc32d6d7981fd4cb33bc0d89bc9b1b699187980");
  const icon=iconFor(app.id);
  assert.equal(icon.bytes.length,16328);
  assert.equal(icon.bytes.readUInt32BE(16),1000);
  assert.equal(icon.bytes.readUInt32BE(20),1000);
  assert(!JSON.stringify(app).includes("https://"));
});

test("Unverified TunnelDOOM updater cannot be invoked through the public broker",async()=>{
  assert(!providerIds().includes("tunneldoom-vpn"));
  assert(!PUBLIC_PROVIDER_IDS.includes("tunneldoom-vpn"));
  assert.equal(providerEnabled("tunneldoom-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
  await assert.rejects(()=>downloadVpnCatalog("tunneldoom-vpn"),{code:"UNSUPPORTED_FORMAT"});
});

test("TunnelDOOM reuses SKS without claiming generic JSON or invented text prefixes",()=>{
  const doc=catalog();
  const file=doc.formats.find(x=>x.suffix==="sks");
  assert(file.name.includes("TunnelDOOM VPN 4.2.4"));
  assert.equal(file.cloudSupported,true);
  assert.deepEqual(file.credentialFields,[]);
  assert.equal(doc.formatCount,254);
  assert(!doc.formats.some(x=>["doom","tdoom","json"].includes(x.suffix)));
  assert(!doc.textFormats.some(x=>/doom/i.test(x.prefix)));
  assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"54"}),55);
  assert.equal(activeCatalogVersion({CLOUD_SERVER_VPN_CATALOG_VERSION:"105"}),105);
});
