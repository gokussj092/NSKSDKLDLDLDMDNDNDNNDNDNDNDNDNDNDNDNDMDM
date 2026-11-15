/** Public build129 Firebase client config. Never contains minted credentials. */
import {randomBytes} from "node:crypto";
import {gzipSync} from "node:zlib";

export const HTTP_CONEXION_FIREBASE_OPTIONS=Object.freeze({"api_key":"AIzaSyCs8YtS4f6yvDiqWdhhWng6YvT6hbyjQmU","app_id":"1:149721662763:android:43dfafdbb13e6a8016b16e","project_id":"http-conexion","certificate_sha1":"38E634DA612E9CAE1D15584EE20A05486F47E04B"});
export const HTTP_CONEXION_CONFIG_TTL_MS=3600000;
export const HTTP_CONEXION_CONFIG_FAILURE_MS=60000;
const PACKAGE="com.doriaxvpn.unlimited";
const token=value=>typeof value==="string"&&/^[!-~]{1,16384}$/.test(value);
const fid=value=>typeof value==="string"&&/^[A-Za-z0-9_-]{22}$/.test(value);

export function approvedHttpConexionSource(value){
  if(typeof value!=="string"||!value.startsWith("https://raw.githubusercontent.com/")||value.length>2048||/[\x00-\x20\x7f\\]/.test(value))throw Error("INVALID_HTTP_CONEXION_CONFIG");
  const url=new URL(value);
  if(url.protocol!=="https:"||url.host!=="raw.githubusercontent.com"||url.username||url.password||
     url.search||url.hash||url.pathname.split("/").length<5)throw Error("INVALID_HTTP_CONEXION_SOURCE");
  return url.href;
}

export function selectHttpConexionConfig(reply){
  const entries=reply?.entries,password=entries?.gretta_pass;
  if(!entries||Array.isArray(entries)||typeof entries!=="object"||typeof password!=="string"||!password||
     password.includes("\0")||Buffer.byteLength(password)>1024||Buffer.from(password).toString("utf8")!==password)
    throw Error("INVALID_HTTP_CONEXION_CONFIG");
  return Object.freeze({source:approvedHttpConexionSource(entries.ockla_url),password});
}

function parse(bytes){
  if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw Error("INVALID_FIREBASE_RESPONSE");
  const result=bytes.length?JSON.parse(bytes.toString("utf8")):{};
  if(!result||typeof result!=="object"||Array.isArray(result))throw Error("INVALID_FIREBASE_RESPONSE");
  return result;
}

export function createHttpConexionResolver(options=HTTP_CONEXION_FIREBASE_OPTIONS){
  let cached=null,expires=0,retryAfter=0,pending=null;
  async function fetch(request){
    const base=`https://firebaseinstallations.googleapis.com/v1/projects/${options.project_id}/installations`;
    const remote=`https://firebaseremoteconfig.googleapis.com/v1/projects/${options.app_id.split(":")[1]}/namespaces/firebase:fetch`;
    const headers={"X-Goog-Api-Key":options.api_key,"X-Android-Package":PACKAGE,"X-Android-Cert":options.certificate_sha1,
      "Content-Type":"application/json",Accept:"application/json","Cache-Control":"no-cache"};
    const bits=randomBytes(17);bits[16]=bits[0];bits[0]=(bits[0]&15)|112;
    let installation;
    try{
      installation=parse(await request(base,{method:"POST",headers:{...headers,"Content-Encoding":"gzip"},
        body:gzipSync(JSON.stringify({fid:bits.toString("base64url").slice(0,22),appId:options.app_id,authVersion:"FIS_v2",sdkVersion:"a:18.0.0"}))}));
      if(!fid(installation.fid)||!token(installation.authToken?.token)||!token(installation.refreshToken))throw Error("INVALID_FIS_RESPONSE");
      const auth=installation.authToken.token;
      const body={appInstanceId:installation.fid,appInstanceIdToken:auth,appId:options.app_id,countryCode:"MX",languageCode:"es-MX",
        platformVersion:"34",timeZone:"America/Tijuana",appVersion:"1.2.9",appBuild:"129",packageName:PACKAGE,
        sdkVersion:"22.1.0",analyticsUserProperties:{}};
      return selectHttpConexionConfig(parse(await request(remote,{method:"POST",headers:{...headers,
        "X-Goog-Firebase-Installations-Auth":auth,"X-Google-GFE-Can-Retry":"yes"},body:Buffer.from(JSON.stringify(body))})));
    }finally{
      if(fid(installation?.fid)&&token(installation?.refreshToken)){
        try{await request(base+"/"+installation.fid,{method:"DELETE",headers:{...headers,Authorization:"FIS_v2 "+installation.refreshToken}});}
        catch{} // Best-effort bounded deletion; never persist or expose tokens.
      }
    }
  }
  return {
    async get(request,{force=false}={}){
      const now=Date.now();
      if(!force&&cached&&now<expires)return cached;
      if(now<retryAfter)throw Error("HTTP_CONEXION_FIREBASE_UNAVAILABLE");
      if(pending)return pending;
      pending=fetch(request).then(value=>{cached=value;expires=Date.now()+HTTP_CONEXION_CONFIG_TTL_MS;retryAfter=0;return value;},()=>{
        cached=null;expires=0;retryAfter=Date.now()+HTTP_CONEXION_CONFIG_FAILURE_MS;
        throw Error("HTTP_CONEXION_FIREBASE_UNAVAILABLE");
      }).finally(()=>{pending=null;});
      return pending;
    },
    clear(){cached=null;expires=0;retryAfter=0;},
  };
}
export const httpConexionResolver=createHttpConexionResolver();

export function packHttpConexionCatalog(bytes,password){
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>8*1024*1024||typeof password!=="string"||!password||
     password.includes("\0")||Buffer.byteLength(password)>1024||Buffer.from(password).toString("utf8")!==password)
    throw Error("INVALID_HTTP_CONEXION_CATALOG");
  const result=Buffer.from(JSON.stringify({kind:"spdecode-http-conexion-config-v1",passwordBase64:Buffer.from(password).toString("base64"),catalogBase64:bytes.toString("base64")}));
  if(result.length>8*1024*1024)throw Error("HTTP_CONEXION_BUNDLE_TOO_LARGE");
  return result;
}
