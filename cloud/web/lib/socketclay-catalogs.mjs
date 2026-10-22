/** Keep both fixed-source responses intact; never return a one-source success. */
import {VpnProviderError} from "./server-vpn-provider.mjs";
export const SOCKETCLAY_BUNDLE_LIMIT=8*1024*1024;
export function packSocketClayCatalogs({servers,users}){
 for(const source of [servers,users])
  if(!Buffer.isBuffer(source)||source.length===0)throw new VpnProviderError("REMOTE_RESPONSE_INVALID");
 const data=Buffer.from(JSON.stringify({kind:"spdecode-socketclay-catalogs-v1",catalogs:{
  servers:servers.toString("base64"),users:users.toString("base64"),
 }}),"utf8");
 if(data.length>SOCKETCLAY_BUNDLE_LIMIT)throw new VpnProviderError("REMOTE_TOO_LARGE");
 return data;
}
