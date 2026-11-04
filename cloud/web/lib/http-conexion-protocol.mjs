/** Fixed build129 updater, confirmed by real Firebase client configuration. */
export const HTTP_CONEXION_SOURCE="https://raw.githubusercontent.com/soportecrisdev/Gen/main/new";
export const HTTP_CONEXION_AGENT="HTTP-Conexion-VPN/3.0";
export const HTTP_CONEXION_HEADERS=Object.freeze({
  Accept:"*/*","Cache-Control":"no-cache, no-store, must-revalidate",Pragma:"no-cache",Expires:"0",
});
export function httpConexionRequestUrl(now=Date.now()){
  if(!Number.isSafeInteger(now)||now<1)throw Error("INVALID_PROVIDER_TIMESTAMP");
  return `${HTTP_CONEXION_SOURCE}?nocache=${now}`;
}
