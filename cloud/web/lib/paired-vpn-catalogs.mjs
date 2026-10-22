/** Both source documents travel intact; missing/oversize sources fail together. */
import {VpnProviderError} from "./server-vpn-provider.mjs";
export const PAIRED_CATALOG_LIMIT=8*1024*1024;
const KINDS=Object.freeze({
 "http-socketclay":"spdecode-socketclay-catalogs-v1",
 "http-wakko":"spdecode-wakko-catalogs-v1",
});
export function packPairedVpnCatalogs(providerId,{servers,users}){
 if(!Object.hasOwn(KINDS,providerId))throw new VpnProviderError("UNSUPPORTED_FORMAT");
 for(const source of [servers,users])
  if(!Buffer.isBuffer(source)||source.length===0)throw new VpnProviderError("REMOTE_RESPONSE_INVALID");
 const data=Buffer.from(JSON.stringify({kind:KINDS[providerId],catalogs:{
  servers:servers.toString("base64"),users:users.toString("base64"),
 }}),"utf8");
 if(data.length>PAIRED_CATALOG_LIMIT)throw new VpnProviderError("REMOTE_TOO_LARGE");
 return data;
}
