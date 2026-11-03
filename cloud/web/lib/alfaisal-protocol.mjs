/** Fixed build39 request recipe. Credential values belong only in backend secrets. */
import {createHmac,randomBytes} from "node:crypto";
export const ALFAISAL_SOURCE="https://panel.alfaisalvpn.com/api/protected_json.php";
export const ALFAISAL_METADATA="https://panel.alfaisalvpn.com/api/app_settings.php";
const names=["SPDECODE_ALFAISAL_API_KEY","SPDECODE_ALFAISAL_SIGNING_KEY","SPDECODE_ALFAISAL_DEVICE_UUID"];
export function alfaisalConfigured(env=process.env){
  const values=names.map(k=>env[k]);
  return values.every(v=>typeof v==="string" && v.length>=16 && v.length<=512 && !/[^!-~]/.test(v)) &&
    /^[A-Za-z0-9_-]{16,128}$/.test(values[2]);
}
export function alfaisalRequest(env=process.env,{timestamp=Math.floor(Date.now()/1000),nonce=randomBytes(16).toString("hex")}={}){
  if(!alfaisalConfigured(env))throw Error("REMOTE_NOT_CONFIGURED");
  const body=Buffer.from(JSON.stringify({device_uuid:env.SPDECODE_ALFAISAL_DEVICE_UUID,
    integrity_token:"",integrity_request_id:"",integrity_request_hash:"",integrity_operation:"json_update",
    json_client_capability:2,json_direct_requested:1}));
  const signature=createHmac("sha256",env.SPDECODE_ALFAISAL_SIGNING_KEY)
    .update(String(timestamp)+".").update(nonce+".").update(body).digest("hex");
  return {body,headers:{"Content-Type":"application/json; charset=utf-8","Accept":"application/json",
    "Cache-Control":"no-cache","X-API-KEY":env.SPDECODE_ALFAISAL_API_KEY,
    "X-TIMESTAMP":String(timestamp),"X-NONCE":nonce,"X-SIGNATURE":signature}};
}
