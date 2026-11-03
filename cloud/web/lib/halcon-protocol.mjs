/** Build1391 updater protocol. Secrets remain server-side and are never logged. */
import {createHash} from "node:crypto";
export const HALCON_SOURCE="https://panel-apk.viofull.com/api_get_config_prod.php";
export function halconConfigured(env=process.env){
  return typeof env.SPDECODE_HALCON_REQUEST_SECRET==="string" &&
    env.SPDECODE_HALCON_REQUEST_SECRET.length===22 &&
    /^[!-~]{22}$/.test(env.SPDECODE_HALCON_REQUEST_SECRET) &&
    typeof env.SPDECODE_HALCON_CATALOG_PASSWORD==="string" &&
    env.SPDECODE_HALCON_CATALOG_PASSWORD.length===129 &&
    /^[!-~]{65}[0-9A-F]{64}$/.test(env.SPDECODE_HALCON_CATALOG_PASSWORD);
}
export function halconRequest(env=process.env,timestamp=Math.floor(Date.now()/1000)){
  if(!halconConfigured(env))throw Error("REMOTE_NOT_CONFIGURED");
  if(!Number.isSafeInteger(timestamp)||timestamp<0||timestamp>999999999999)throw Error("INVALID_TIMESTAMP");
  const stamp=String(timestamp);
  const signature=createHash("sha256").update(stamp+env.SPDECODE_HALCON_REQUEST_SECRET,"utf8").digest("hex");
  return {headers:{"Content-Type":"application/x-www-form-urlencoded","X-Auth-Hash":signature,
    "X-Timestamp":stamp,"X-App-ID":"HalconRNet_2026"},
    body:Buffer.from(new URLSearchParams({hash:signature,timestamp:stamp}).toString())};
}
