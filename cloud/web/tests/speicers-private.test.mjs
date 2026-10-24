import test from "node:test";
import assert from "node:assert/strict";
import {catalog,CATALOG_VERSION,iconFor} from "../lib/server-vpn-catalog.mjs";
import {providerIds,providerEnabled} from "../lib/server-vpn-provider.mjs";

test("Speicers stays absent from public metadata and download broker even with global enablement",()=>{
  const before=process.env.CLOUD_SERVER_VPN_ENABLED;
  process.env.CLOUD_SERVER_VPN_ENABLED="true";
  try {
    const doc=catalog({availability:{"speicers-pro-vpn":true}});
    assert.equal(doc.apps.length,40);
    assert.equal(CATALOG_VERSION,40);
    assert.ok(!doc.apps.some(x=>/speicers/i.test(x.id+" "+x.name)));
    assert.ok(!providerIds().includes("speicers-pro-vpn"));
    assert.equal(providerEnabled("speicers-pro-vpn",{CLOUD_SERVER_VPN_ENABLED:"true"}),false);
    assert.equal(iconFor("speicers-pro-vpn"),null);
  } finally {
    if(before===undefined)delete process.env.CLOUD_SERVER_VPN_ENABLED;
    else process.env.CLOUD_SERVER_VPN_ENABLED=before;
  }
});
