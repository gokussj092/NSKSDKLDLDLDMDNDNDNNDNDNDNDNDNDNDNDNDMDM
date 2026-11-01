/** Public catalog presentation only: no provider credentials or vendor endpoints. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";
import {publicFormats,FORMAT_DETECTION} from "./file-format-catalog.mjs";
import {publicTextFormats,publicOnlineReferenceFormats} from "./text-format-catalog.mjs";

export const CATALOG_VERSION = 59; // Same pending server release 59, per owner instruction.
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
  // Build 29 embedded catalog verified; anonymous updater requests return HTTP 404.
  {id:"vip-snipher-pro", name:"VIP Snipher Pro", icon:"vip-snipher-pro.png", remote:null},
  {id:"netcol-vpn", name:"Netcol VPN", icon:"netcol-vpn.png", remote:"netcol-vpn"},
  {id:"wolf-custom-vpn", name:"Wolf Custom VPN", icon:"wolf-custom-vpn.png", remote:"wolf-custom-vpn"},
  {id:"jyfast-vpn-ultra", name:"JyFast VPN Ultra", icon:"jyfast-vpn-ultra.png", remote:"jyfast-vpn-ultra"},
  // Build 430 fixed updater validated against the complete real catalog.
  {id:"tunneldoom-vpn", name:"TunnelDOOM VPN", icon:"tunneldoom-vpn.png", remote:"tunneldoom-vpn"},
  // DexProtector resources and the fixed updater still require runtime verification.
  {id:"ha-tunnel-plus", name:"HA Tunnel Plus", icon:"ha-tunnel-plus.png", remote:null},
  {id:"mtm-tunnel-lite", name:"MTM Tunnel Lite", icon:"mtm-tunnel-lite.png", remote:"mtm-tunnel-lite"},
  {id:"mnr-tunnel-plus", name:"MNR TUNNEL PLUS", icon:"mnr-tunnel-plus.png", remote:"mnr-tunnel-plus"},
  {id:"bd-net-vpn", name:"BD NET VPN", icon:"bd-net-vpn.png", remote:"bd-net-vpn"},
  {id:"aura-net-vpn", name:"Aura Net VPN", icon:"aura-net-vpn.png", remote:"aura-net-vpn"},
  {id:"apna-vpn", name:"APNA VPN", icon:"apna-vpn.png", remote:"apna-vpn"},
  {id:"any-vpn", name:"ANY VPN", icon:"any-vpn.png", remote:"any-vpn"},
  {id:"speicers-pro-vpn", name:"Speicers Pro VPN", icon:"speicers-pro-vpn.png", remote:"speicers-pro-vpn"},
  {id:"tx-tunnel", name:"Tx Tunnel", icon:"tx-tunnel.png", remote:"tx-tunnel"},
  // Embedded catalog verified; official fixed POST returned HTTP 403.
  {id:"mm-tunnel", name:"MM Tunnel", icon:"mm-tunnel.png", remote:null},
  // Embedded catalog works; remote Play Integrity response remains unvalidated.
  {id:"creeb-vpn", name:"CREEB VPN", icon:"creeb-vpn.png", remote:null},
  {id:"abowaged-vpn", name:"AboWaged VPN", icon:"abowaged-vpn.png", remote:"abowaged-vpn"},
  // Build 63 outer catalog remains protected; fixed source timed out during analysis.
  {id:"am-tunnel-lite-vpn", name:"AM TUNNEL LITE VPN", icon:"am-tunnel-lite-vpn.png", remote:null},
  {id:"7net-vpn", name:"7NET VPN", icon:"7net-vpn.png", remote:"7net-vpn"},
  {id:"xhypher-tunnel-pro", name:"Xhypher Tunnel Pro", icon:"xhypher-tunnel-pro.png", remote:"xhypher-tunnel-pro"},
  // Official endpoint returns HTML; a valid signed OTA response is still required.
  {id:"ut-loop-pro-vpn", name:"UT Loop Pro VPN", icon:"ut-loop-pro-vpn.png", remote:null},
  {id:"turbomx-vpn", name:"TurboMX VPN", icon:"turbomx-vpn.png", remote:"turbomx-vpn"},
  {id:"superflash-vpn", name:"SuperFlash VPN", icon:"superflash-vpn.png", remote:"superflash-vpn"},
  {id:"rmp-tunnel-pro", name:"RMP TUNNEL PRO", icon:"rmp-tunnel-pro.png", remote:"rmp-tunnel-pro"},
  {id:"rjc-tunnel-pro", name:"RJC TUNNEL PRO", icon:"rjc-tunnel-pro.png", remote:"rjc-tunnel-pro"},
  // Build 88 updater files currently contain only a newline; offline catalogs work.
  {id:"proneet-vpn", name:"ProNeet VPN", icon:"proneet-vpn.png", remote:null},
  {id:"onspace-vpn", name:"OnSpace VPN", icon:"onspace-vpn.png", remote:"onspace-vpn"},
  {id:"mx-tunnel-pro", name:"Mx Tunnel PRO", icon:"mx-tunnel-pro.png", remote:"mx-tunnel-pro"},
  {id:"megatunnel", name:"MegaTunnel", icon:"megatunnel.png", remote:"megatunnel"},
  {id:"http-internet-infinito", name:"HTTP Internet Infinito", icon:"http-internet-infinito.png", remote:"http-internet-infinito"},
  {id:"freedom-vpn", name:"FreedomVPN", icon:"freedom-vpn.png", remote:"freedom-vpn"},
  {id:"focus-vpn-cloud", name:"Focus VPN Cloud", icon:"focus-vpn-cloud.png", remote:"focus-vpn-cloud"},
  // Build 370 resources require an official session; API rejects this environment.
  {id:"eut-vpn", name:"EUT VPN", icon:"eut-vpn.png", remote:null},
  {id:"v2ray-tunnel-plus", name:"V2ray Tunnel Plus", icon:"v2ray-tunnel-plus.png", remote:"v2ray-tunnel-plus"},
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
    // Additive: old APKs only consume apps and ignore these optional fields.
    formatsSchemaVersion:1,
    formatDetection:FORMAT_DETECTION,
    formatCount:publicFormats().length,
    formats:publicFormats(),
    textSchemaVersion:1,
    textCount:publicTextFormats().length,
    textFormats:publicTextFormats(),
    onlineReferencesSchemaVersion:1,
    onlineReferenceCount:publicOnlineReferenceFormats().length,
    onlineReferenceFormats:publicOnlineReferenceFormats(),
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
