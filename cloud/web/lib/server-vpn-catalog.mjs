/** Public catalog presentation only: no provider credentials or vendor endpoints. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";

export const CATALOG_VERSION = 17; // Increment whenever the public roster or metadata changes.
export const RECHECK_SECONDS = 15 * 60; // Version-only recovery; full download occurs on version change.

/** Monotonic deployment version. Bump this override for ANY metadata, icon
 * or provider enablement change, before the server rollout. */
export function activeCatalogVersion(env=process.env) {
  const configured=env.CLOUD_SERVER_VPN_CATALOG_VERSION;
  if(configured===undefined || configured==="")return CATALOG_VERSION;
  if(!/^[1-9][0-9]{0,8}$/.test(configured))throw Error("INVALID_CATALOG_VERSION");
  const number=Number(configured);
  if(!Number.isSafeInteger(number) || number<11)
    throw Error("CATALOG_VERSION_ROLLBACK");
  // Existing VPS installations may still pin version 11 or 12 in cloud.env.
  // Keep the effective version monotonic for new icon and roster metadata.
  return Math.max(number,CATALOG_VERSION);
}

const ITEMS = Object.freeze([
  // Build 128 updater returns HTTP 404; offline reader is validated.
  {id:"tunelguard-vpn", name:"TunelGuard VPN", icon:"tunelguard-vpn.png", remote:null},
  {id:"http-wakko", name:"HTTP Wakko", icon:"http-wakko.png", remote:"http-wakko"},
  {id:"http-socketclay", name:"HTTP SocketClay", icon:"http-socketclay.png", remote:"http-socketclay"},
  {id:"tunneltweak", name:"Tunneltweak", icon:"tunneltweak.png", remote:"tunneltweak"},
  {id:"http-jireh", name:"HTTP Jireh", icon:"http-jireh.png", remote:"http-jireh"},
  {id:"http-fenixvpn", name:"HTTP FenixVPN", icon:"http-fenixvpn.png", remote:"http-fenixvpn"},
  {id:"austroplus-vpn", name:"AustroPlus VPN", icon:"austroplus-vpn.png", remote:"austroplus-vpn"},
  {id:"ac-tunnel-vpn", name:"AC TUNNEL VPN", icon:"ac-tunnel-vpn.png", remote:"ac-tunnel-vpn"},
  {id:"nur-tunnel", name:"NUR TUNNEL VPN", icon:"nur-tunnel.png", remote:"nur"},
  {id:"24clan-green", name:"24clan VPN Green", icon:"24clan-green.png", remote:"24clan-green"},
  {id:"hx-tunnel", name:"HX Tunnel VPN", icon:"hx-tunnel.png", remote:"hx-tunnel"},
  {id:"mkk-hyper", name:"MKK Hyper VPN", icon:"mkk-hyper.png", remote:"mkk-hyper"},
  {id:"ksh-vpn", name:"KSH VPN", icon:"ksh-vpn.png", remote:"ksh-vpn"},
  {id:"my-tunnel-proxy", name:"My Tunnel Proxy", icon:"my-tunnel-proxy.png", remote:"my-tunnel-proxy"},
  {id:"robust-tunnel", name:"Robust Tunnel VPN", icon:"robust-tunnel.png", remote:"robust-tunnel"},
  {id:"trv-tunnel", name:"TRV TUNNEL", icon:"trv-tunnel.png", remote:"trv-tunnel"},
  {id:"4u-tunnel-lite", name:"4U TUNNEL LITE", icon:"4u-tunnel-lite.png", remote:"4u-tunnel-lite"},
  // DTunnel Mod can decrypt offline, but remote catalogs require a private
  // account identifier. Show the owner-confirmed icon; do not enable download.
  {id:"dtunnel-mod", name:"DTunnel Mod", icon:"dtunnel-mod.png", remote:null},
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
export function catalog({availability=null,version=activeCatalogVersion()}={}) {
  return {
    apiVersion:"v1",
    catalogVersion:version,
    recheckAfterSeconds:RECHECK_SECONDS,
    apps: ITEMS.map(x=>({
      id:x.id,
      name:x.name,
      iconSha256:iconFor(x.id).sha256,
      iconMimeType:"image/png",
      // No decode button for a provider until its remote broker is enabled.
      decodeEnabled:x.remote==="nur" ? (availability?.["nur-tunnel"] ?? process.env.CLOUD_NUR_FETCH_ENABLED==="true") :
        Boolean(x.remote) && (availability?.[x.id] ?? process.env.CLOUD_SERVER_VPN_ENABLED==="true"),
    })),
  };
}
