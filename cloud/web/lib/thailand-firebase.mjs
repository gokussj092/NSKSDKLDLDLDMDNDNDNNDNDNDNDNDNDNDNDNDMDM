/** Public Thailand build3 Firebase client config. Never contains minted credentials. */
import {randomBytes} from "node:crypto";
import {gzipSync} from "node:zlib";

export const THAILAND_FIREBASE_OPTIONS=Object.freeze({"api_key":"AIzaSyDHaIOwa7qoESPpRS5lXyVZixYOS5sIkW4","app_id":"1:376598045006:android:778874487f5eed6db2be1f","project_id":"thiland-vpn","certificate_sha1":"CFF514C9000704D8D59F28D7FFBB960EC22C2C00"});
export const THAILAND_CONFIG_TTL_MS=3600000;
export const THAILAND_CONFIG_FAILURE_MS=60000;
const PACKAGE="thailand.vpn.globalvpn";
const token=value=>typeof value==="string"&&/^[!-~]{1,16384}$/.test(value);
const fid=value=>typeof value==="string"&&/^[A-Za-z0-9_-]{22}$/.test(value);

export function approvedThailandSource(value){
  if(typeof value!=="string"||value.length>2048||/[\x00-\x20\x7f\\]/.test(value))throw Error("INVALID_THAILAND_SOURCE");
  const url=new URL(value);
  if(url.protocol!=="https:"||url.host!=="globalvpn.uk"||url.username||url.password||url.search||url.hash||
     !["/global_admin/api/","/global_admin/api"].includes(url.pathname))throw Error("INVALID_THAILAND_SOURCE");
  return "https://globalvpn.uk/global_admin/api/server?package_name=thailand.vpn.globalvpn";
}
export function selectThailandConfig(reply){
  return Object.freeze({source:approvedThailandSource(reply?.entries?.serverUrl)});
}

function parse(bytes){
  if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024)throw Error("INVALID_FIREBASE_RESPONSE");
  const result=bytes.length?JSON.parse(bytes.toString("utf8")):{};
  if(!result||typeof result!=="object"||Array.isArray(result))throw Error("INVALID_FIREBASE_RESPONSE");
  return result;
}

export function createThailandResolver(options=THAILAND_FIREBASE_OPTIONS){
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
        platformVersion:"34",timeZone:"America/Tijuana",appVersion:"1.0.3",appBuild:"3",packageName:PACKAGE,
        sdkVersion:"22.1.0",analyticsUserProperties:{}};
      return selectThailandConfig(parse(await request(remote,{method:"POST",headers:{...headers,
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
      if(now<retryAfter)throw Error("THAILAND_FIREBASE_UNAVAILABLE");
      if(pending)return pending;
      pending=fetch(request).then(value=>{cached=value;expires=Date.now()+THAILAND_CONFIG_TTL_MS;retryAfter=0;return value;},()=>{
        cached=null;expires=0;retryAfter=Date.now()+THAILAND_CONFIG_FAILURE_MS;
        throw Error("THAILAND_FIREBASE_UNAVAILABLE");
      }).finally(()=>{pending=null;});
      return pending;
    },
    clear(){cached=null;expires=0;retryAfter=0;},
  };
}
export const thailandResolver=createThailandResolver();
