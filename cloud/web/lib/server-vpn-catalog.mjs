/** Public catalog presentation only: no provider credentials or vendor endpoints. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {createHash} from "node:crypto";

export const CATALOG_VERSION = 1; // Increment whenever the public roster or metadata changes.
export const RECHECK_SECONDS = 24 * 60 * 60;
const ITEMS = Object.freeze([
  {id:"nur-tunnel", name:"NUR TUNNEL VPN", icon:"nur-tunnel.png", remote:"nur"},
  {id:"24clan-green", name:"24clan VPN Green", icon:"24clan-green.png", remote:null},
  {id:"hx-tunnel", name:"HX Tunnel VPN", icon:"hx-tunnel.png", remote:null},
  {id:"mkk-hyper", name:"MKK Hyper VPN", icon:"mkk-hyper.png", remote:null},
]);

const base = () => join(process.cwd(),"public","server-vpn-icons");
export function iconFor(id) {
  const item = ITEMS.find(x => x.id === id);
  if (!item) return null;
  const bytes = readFileSync(join(base(),item.icon));
  if (!bytes.length || bytes.length > 256*1024) throw Error("INVALID_ORIGINAL_ICON");
  return {id:item.id, bytes, sha256:createHash("sha256").update(bytes).digest("hex")};
}
export function catalog() {
  return {
    apiVersion:"v1",
    catalogVersion:CATALOG_VERSION,
    recheckAfterSeconds:RECHECK_SECONDS,
    apps: ITEMS.map(x=>({
      id:x.id,
      name:x.name,
      iconSha256:iconFor(x.id).sha256,
      iconMimeType:"image/png",
      // No decode button for a provider until its remote broker is enabled.
      decodeEnabled:x.remote==="nur" && process.env.CLOUD_NUR_FETCH_ENABLED==="true",
    })),
  };
}
