/** Public catalog presentation only: no provider credentials or vendor endpoints. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";

export const CATALOG_VERSION = 8; // Increment whenever the public roster or metadata changes.
export const RECHECK_SECONDS = 24 * 60 * 60;

/** Monotonic deployment version. Bump this override for ANY metadata, icon
 * or provider enablement change, before the server rollout. */
export function activeCatalogVersion(env=process.env) {
  const configured=env.CLOUD_SERVER_VPN_CATALOG_VERSION;
  if(configured===undefined || configured==="")return CATALOG_VERSION;
  if(!/^[1-9][0-9]{0,8}$/.test(configured))throw Error("INVALID_CATALOG_VERSION");
  const number=Number(configured);
  if(!Number.isSafeInteger(number) || number<CATALOG_VERSION)
    throw Error("CATALOG_VERSION_ROLLBACK");
  return number;
}

const ITEMS = Object.freeze([
  {id:"austroplus-vpn", name:"AustroPlus VPN", icon:"austroplus-vpn.png", remote:"austroplus-vpn"},
  {id:"ac-tunnel-vpn", name:"AC TUNNEL VPN", icon:"ac-tunnel-vpn.png", remote:"ac-tunnel-vpn"},
  {id:"nur-tunnel", name:"NUR TUNNEL VPN", icon:"nur-tunnel.png", remote:"nur"},
  {id:"24clan-green", name:"24clan VPN Green", icon:"24clan-green.png", remote:"24clan-green"},
  {id:"hx-tunnel", name:"HX Tunnel VPN", icon:"hx-tunnel.png", remote:"hx-tunnel"},
  {id:"mkk-hyper", name:"MKK Hyper VPN", icon:"mkk-hyper.png", remote:"mkk-hyper"},
  {id:"my-tunnel-proxy", name:"My Tunnel Proxy", icon:"my-tunnel-proxy.png", remote:"my-tunnel-proxy"},
  {id:"robust-tunnel", name:"Robust Tunnel VPN", icon:"robust-tunnel.png", remote:"robust-tunnel"},
  {id:"trv-tunnel", name:"TRV TUNNEL", icon:"trv-tunnel.png", remote:"trv-tunnel"},
  {id:"4u-tunnel-lite", name:"4U TUNNEL LITE", icon:"4u-tunnel-lite.png", remote:"4u-tunnel-lite"},
  // Keep Royal's original icon visible while its live catalog remains unvalidated.
  {id:"royal-tunnel", name:"Royal Tunnel VPN", icon:"royal-tunnel.png", remote:null},
]);

const base = () => join(process.cwd(),"public","server-vpn-icons");
export function iconFor(id) {
  const item = ITEMS.find(x => x.id === id);
  if (!item) return null;
  const bytes = readFileSync(join(base(),item.icon));
  if (bytes.length<32 || bytes.subarray(0,8).toString("hex")!=="89504e470d0a1a0a")
    throw Error("INVALID_ORIGINAL_ICON");
  return {id:item.id, bytes, sha256:createHash("sha256").update(bytes).digest("hex")};
}
export function catalog() {
  return {
    apiVersion:"v1",
    catalogVersion:activeCatalogVersion(),
    recheckAfterSeconds:RECHECK_SECONDS,
    apps: ITEMS.map(x=>({
      id:x.id,
      name:x.name,
      iconSha256:iconFor(x.id).sha256,
      iconMimeType:"image/png",
      // No decode button for a provider until its remote broker is enabled.
      decodeEnabled:x.remote==="nur" ? process.env.CLOUD_NUR_FETCH_ENABLED==="true" :
        Boolean(x.remote) && process.env.CLOUD_SERVER_VPN_ENABLED==="true",
    })),
  };
}
