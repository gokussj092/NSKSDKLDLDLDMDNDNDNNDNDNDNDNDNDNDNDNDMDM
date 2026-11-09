/** CATNET Play build29: original static client metadata; never invent Play tokens. */
import {randomUUID} from "node:crypto";
export const CATNET_SOURCE="https://pussyvpn.com/xjvpn/mobile/public/servers";
export const CATNET_BUILD=29;
export const CATNET_PREFLIGHT="https://pussyvpn.com/xjvpn/mobile/public/app-update?app_key=pussy_vpn&current_version_code="+CATNET_BUILD;
export const CATNET_AGENT="okhttp/4.12.0";
export function catnetHeaders(){
 return {"X-XJ-App-Key":"pussy_vpn","X-App-Key":"pussy_vpn",
  "X-XJ-App-Package":"net.catnet.vpn","X-App-Package":"net.catnet.vpn",
  "X-Package-Name":"net.catnet.vpn","X-XJ-Package-Name":"net.catnet.vpn",
  "X-XJ-Version-Code":String(CATNET_BUILD),"X-XJ-Installation-Id":randomUUID()};
}
export function catnetPreflight(data){
 const doc=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));
 const info=doc?.data;
 if(doc?.success!==true||!info||typeof info!=="object"||Array.isArray(info))throw Error("REMOTE_RESPONSE_INVALID");
 if(info.maintenance===true)throw Error("REMOTE_PROVIDER_UNAVAILABLE");
 if(info.integrity_required!==false)throw Error("REMOTE_NOT_CONFIGURED");
}
