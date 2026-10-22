/** Both source documents travel intact; missing/oversize sources fail together. */
import {VpnProviderError} from "./server-vpn-provider.mjs";
export const PAIRED_CATALOG_LIMIT=8*1024*1024;
const KINDS=Object.freeze({
 "http-socketclay":{kind:"spdecode-socketclay-catalogs-v1",sources:["servers","users"]},
 "http-wakko":{kind:"spdecode-wakko-catalogs-v1",sources:["servers","users"]},
 "v2ray-tunnel-plus":{kind:"spdecode-v2ray-tunnel-plus-catalogs-v1",sources:["base64","raw"]},
});
export function packPairedVpnCatalogs(providerId,sources){
 if(!Object.hasOwn(KINDS,providerId))throw new VpnProviderError("UNSUPPORTED_FORMAT");
 const config=KINDS[providerId];
 if(!sources||Object.keys(sources).sort().join(",")!==[...config.sources].sort().join(","))throw new VpnProviderError("REMOTE_RESPONSE_INVALID");
 const catalogs={};
 for(const name of config.sources){
  const source=sources[name];
  if(!Buffer.isBuffer(source)||source.length===0)throw new VpnProviderError("REMOTE_RESPONSE_INVALID");
  catalogs[name]=source.toString("base64");
 }
 const data=Buffer.from(JSON.stringify({kind:config.kind,catalogs}),"utf8");
 if(data.length>PAIRED_CATALOG_LIMIT)throw new VpnProviderError("REMOTE_TOO_LARGE");
 return data;
}
