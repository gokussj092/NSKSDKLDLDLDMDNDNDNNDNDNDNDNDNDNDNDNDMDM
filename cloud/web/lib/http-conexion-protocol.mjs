import {approvedHttpConexionSource} from "./http-conexion-firebase.mjs";
/** Historical observed source; online requests resolve a fresh Firebase pair. */
export const HTTP_CONEXION_SOURCE="https://raw.githubusercontent.com/soportecrisdev/Gen/main/new";
export const HTTP_CONEXION_AGENT="HTTP-Conexion-VPN/3.0";
export const HTTP_CONEXION_HEADERS=Object.freeze({
  Accept:"*/*","Cache-Control":"no-cache, no-store, must-revalidate",Pragma:"no-cache",Expires:"0",
});
export function httpConexionRequestUrl(now=Date.now(),source=HTTP_CONEXION_SOURCE){
  if(!Number.isSafeInteger(now)||now<1)throw Error("INVALID_PROVIDER_TIMESTAMP");
  return `${approvedHttpConexionSource(source)}?nocache=${now}`;
}
