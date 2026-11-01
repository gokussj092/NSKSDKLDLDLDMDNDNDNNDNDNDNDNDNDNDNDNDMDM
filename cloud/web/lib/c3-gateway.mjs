import { randomUUID, createPrivateKey, createPublicKey, createHash, ECDH } from "node:crypto";
import { settings, limits } from "./c3-config.mjs";
import { v2Settings } from "./v2-config.mjs";
import { store, reserveSlot, releaseSlot } from "./c3-store.mjs";
import { createChallenge, issueSession, issueQaSession, requireSession } from "./c3-session.mjs";
import { jsonReply, unavailable } from "./responses.mjs";
import { legacyCredentialError } from "./decoder-client-compat.mjs";
import { ehiConfigured, nurConfigured, importMnrReference, importHttpCustomReference, isHttpCustomReference, isHttpCustomLegacyReference, parseHttpCustomLegacyReference, isExternalImportError } from "./c35-provider.mjs";
import {providerAllowed} from "./c12-provider-controls.mjs";
import { maintenanceEnabled, serviceMaintenanceEnabled, recordWorkerResult } from "./c6-ops-store.mjs";
import {admissionPolicy} from "./c11-play-admission.mjs";
import {publicFormats} from "./file-format-catalog.mjs";

import {negotiatesExport,exportPolicy,exportAllowed,EXPORT_PROFILE} from "./compatible-export-policy.mjs";

const ERROR_MESSAGES = Object.freeze({
  INVALID_REQUEST:"Solicitud inválida.",
  EXPORT_CLIENT_UNSUPPORTED:"Actualiza SP-DECODE para utilizar la exportación compatible.",
  UNAUTHORIZED:"Sesión no autorizada o caducada.",
  RATE_LIMITED:"Límite de solicitudes alcanzado.",
  INPUT_TOO_LARGE:"Archivo o texto demasiado grande.",
  UNSUPPORTED_FORMAT:"Formato no reconocido por el servidor.",
  UNSUPPORTED_VERSION:"La versión de este archivo aún no está integrada.",
  UNSUPPORTED_METHOD:"Este método de protección aún no está integrado.",
  UNSUPPORTED_VARIANT:"Esta variante todavía no es compatible o el archivo ha sido modificado.",
  INVALID_INPUT:"Entrada inválida.",
  INVALID_BASE64:"Archivo Base64 inválido.",
  INVALID_CREDENTIALS:"Credenciales inválidas.",
  PASSWORD_REQUIRED:"Se requiere contraseña.",
  HWID_REQUIRED:"Se requiere HWID.",
  HWID_PASSWORD_REQUIRED:"Se requieren contraseña y HWID.",
  AUTH_FAILED:"No se pudo autenticar el archivo.",
  DECODE_FAILED:"No se pudo descifrar el archivo.",
  NPVS_PROTECTION_UNSUPPORTED:"Esta variante de protección NPVS aún no está implementada.",
  NPVS_APPKEY_AUTH_FAILED:"La clave de aplicación NPVS no pudo autenticarse; puede ser una variante diferente o un archivo modificado.",
  PRIVATE_KEY_REQUIRED:"Este archivo requiere la clave privada del dispositivo destinatario; la clave pública sola no permite descifrarlo.",
  RECIPIENT_MISMATCH:"La clave pública no corresponde a un destinatario de este archivo.",
  ENGINE_TIMEOUT:"El motor agotó el tiempo disponible.",
  ENGINE_UNAVAILABLE:"Motor temporalmente no disponible.",
  OUTPUT_TOO_LARGE:"Resultado demasiado grande.",
  EXPIRED_CHALLENGE:"El desafío expiró o ya fue utilizado.",
  INTEGRITY_REJECTED:"No se pudo verificar la integridad de la aplicación.",
  SERVICE_UNAVAILABLE:"Servicio temporalmente no disponible.",
  SERVICE_MAINTENANCE:"Este descifrador está temporalmente en mantenimiento.",
  QA_DISABLED:"El acceso de pruebas ya no está habilitado.",
  QA_ACCESS_DENIED:"Código temporal de pruebas inválido o expirado.",
  INVALID_REFERENCE:"Referencia remota inválida.",
  USER_CONSENT_REQUIRED:"Se requiere autorización expresa para importar.",
  REMOTE_NOT_CONFIGURED:"Importación remota no configurada.",
  REMOTE_NETWORK_DENIED:"Destino remoto no autorizado.",
  REMOTE_PROVIDER_UNAVAILABLE:"El proveedor remoto no respondió.",
  REMOTE_CONFIG_UNAVAILABLE:"Esta configuración Cloud ya no está disponible. Puede haber caducado, haberse eliminado o ser de un solo uso.",
  REMOTE_RESPONSE_INVALID:"El proveedor devolvió una respuesta inválida.",
  REMOTE_INTEGRITY_FAILED:"Falló la integridad de la respuesta remota.",
  REMOTE_TOO_LARGE:"El contenido remoto excede el límite.",
  REMOTE_DECODER_FAILED:"No se pudo descifrar la configuración remota.",
});
export function failure(code,status=400) {
  const message = ERROR_MESSAGES[code] || ERROR_MESSAGES.SERVICE_UNAVAILABLE;
  return jsonReply({apiVersion:"v1",status:"error",error:{code,message}},status,
    status===429?{"Retry-After":"60"}:{});
}
export function enabled() { return settings().configured; }
export function notEnabled() { return unavailable(); }

export async function boundedBody(request,maxBytes) {
  if (!request || request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "application/json")
    throw Object.assign(new Error("content type"),{code:"INVALID_REQUEST"});
  const advertised=request.headers.get("content-length");
  if (advertised && (!/^\d+$/.test(advertised) || Number(advertised)>maxBytes))
    throw Object.assign(new Error("oversized"),{code:"INPUT_TOO_LARGE"});
  if (!request.body) throw Object.assign(new Error("missing body"),{code:"INVALID_REQUEST"});
  const stream=request.body.getReader(),chunks=[];
  let used=0;
  try {
    while(true){
      const {done,value}=await stream.read();
      if(done)break;
      used+=value.byteLength;
      if(used>maxBytes)throw Object.assign(new Error("oversized"),{code:"INPUT_TOO_LARGE"});
      chunks.push(value);
    }
  } finally { stream.releaseLock(); }
  try { return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks))); }
  catch { throw Object.assign(new Error("not JSON"),{code:"INVALID_REQUEST"}); }
}
const isRecord = obj => obj && typeof obj==="object" && !Array.isArray(obj);
const encodedBytes = value => {
  if (typeof value!=="string" || !value || value.length> Math.ceil(limits.maxPublicFileBytes/3)*4 + 8 ||
      value.length%4!==0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value))
    throw Object.assign(new Error("bad base64"),{code:"INVALID_BASE64"});
  const data=Buffer.from(value,"base64");
  if (!data.length || data.length>limits.maxPublicFileBytes || data.toString("base64")!==value)
    throw Object.assign(new Error("bad base64"),{code:"INVALID_BASE64"});
  return true;
};
function validatePayload(kind,payload) {
  if (!isRecord(payload))throw Object.assign(new Error("schema"),{code:"INVALID_REQUEST"});
  if(kind==="file"){
    if (Object.keys(payload).some(x=>!["format","dataBase64","credentials","compatibleExport"].includes(x)) ||
        typeof payload.format!=="string" || !/^[\p{L}\p{N}][\p{L}\p{N}._-]{0,63}$/u.test(payload.format))
      throw Object.assign(new Error("format"),{code:"INVALID_REQUEST"});
    if(payload.compatibleExport!==undefined){
      const e=payload.compatibleExport;
      if(!isRecord(e)||Object.keys(e).some(k=>!["profile","language"].includes(k))||
        e.profile!==EXPORT_PROFILE||(e.language!==undefined&&!["es","en"].includes(e.language)))
        throw Object.assign(new Error("export schema"),{code:"INVALID_REQUEST"});
    }
    if (payload.credentials!==undefined){
      // Metadata is curated and validated on the server. Never trust an
      // Android-supplied credential policy or executable route.
      const allowed=publicFormats().find(entry=>entry.suffix===payload.format)?.credentialFields;

      if (!allowed?.length || !isRecord(payload.credentials) ||
          Object.keys(payload.credentials).some(k=>!allowed.includes(k)))
        throw Object.assign(new Error("credentials"),{code:"INVALID_CREDENTIALS"});
      for(const [key,max] of [["password",4096],["hwid",128],["publicKey",128],["recipientKey",16384]]){
        const value=payload.credentials[key];
        if(value!==undefined && (typeof value!=="string" || !value.length || value.length>max ||
            (["1ftnl","npvs"].includes(payload.format) && Buffer.byteLength(value,"utf8")>max)))
          throw Object.assign(new Error("credentials"),{code:"INVALID_CREDENTIALS"});
      }
    }
    encodedBytes(payload.dataBase64);
  } else if(kind==="text"){
    if(Object.keys(payload).some(key=>!["text","credentials"].includes(key)) ||
       typeof payload.text!=="string" || !payload.text.trim() ||
       payload.text.length>limits.maxPublicTextChars)
       throw Object.assign(new Error("text"),{code:"INVALID_REQUEST"});
    if(payload.credentials!==undefined){
      const pass=payload.credentials?.password;
      const value=payload.text.trim();
      const hc=isHttpCustomReference(value);
      if(hc){
        if(!isRecord(payload.credentials) || Object.keys(payload.credentials).some(key=>!["password","hwid"].includes(key)) ||
            Object.entries(payload.credentials).some(([key,val])=>typeof val!=="string" || !val.length ||
              Buffer.byteLength(val,"utf8")>(key==="password"?4096:128)))
          throw Object.assign(new Error("credentials"),{code:"INVALID_CREDENTIALS"});
        return;
      }
      const passwordFormat=value.toLowerCase().startsWith("ua://") ||
        ["1FTnl.","1FT1.","1ftunnel://1FTnl/","1ftunnel://1FT1/"].some(prefix=>value.startsWith(prefix)) ||
        ["npvt://","npvt-ssh://","npvt-vless://","npvt-vmess://","npv://"].some(prefix=>
          value.toLowerCase().startsWith(prefix) && value.length>prefix.length);
      if(!passwordFormat ||
         !isRecord(payload.credentials) || Object.keys(payload.credentials).length!==1 ||
         typeof pass!=="string" || !pass.length || Buffer.byteLength(pass,"utf8")>4096)
        throw Object.assign(new Error("credentials"),{code:"INVALID_CREDENTIALS"});
    }
  } else if(kind==="catalog"){
    if(Object.keys(payload).length!==1)throw Object.assign(new Error("catalog"),{code:"INVALID_REQUEST"});
    encodedBytes(payload.dataBase64);
  } else throw Object.assign(new Error("kind"),{code:"INVALID_REQUEST"});
}
export async function fetchWorker(kind,payload,cfg,{fetchImpl=fetch}={}) {
  const base=process.env.WORKER_INTERNAL_URL || "";
  // Not an arbitrary proxy. Only Docker service DNS, no client URL or egress.
  if(base!=="http://decoder-worker:8787")throw Error("UNSAFE_WORKER_ORIGIN");
  const suffix={file:"file",text:"text",catalog:"import/catalog","server-vpn":"import/server-vpn"}[kind];
  const response=await fetchImpl(base+"/internal/v1/decode/"+suffix,{
    method:"POST",signal:AbortSignal.timeout((kind==="catalog"||kind==="server-vpn")?135000:
      kind==="file"&&payload.compatibleExport?50000:25000),
    headers:{"Content-Type":"application/json","X-SP-Worker-Token":cfg.workerToken},
    body:JSON.stringify(payload),
    redirect:"error",
    cache:"no-store",
  });
  // MKK is the only catalog allowed a larger internal result. Bound bytes as
  // they arrive so a malicious or broken worker cannot exhaust broker memory.
  const isMkk=kind==="server-vpn" && payload?.providerId==="mkk-hyper";
  const responseLimit=isMkk?96*1024*1024:6*1024*1024;
  const advertised=response.headers?.get?.("content-length");
  if(advertised && /^[0-9]+$/.test(advertised) && Number(advertised)>responseLimit)
    throw Error("OUTPUT_OVER_LIMIT");
  let value;
  if(response.body?.getReader){
    const reader=response.body.getReader(),chunks=[];
    let received=0;
    try{
      while(true){
        const item=await reader.read();
        if(item.done)break;
        received+=item.value.byteLength;
        if(received>responseLimit)throw Error("OUTPUT_OVER_LIMIT");
        chunks.push(Buffer.from(item.value));
      }
    }finally{
      if(received>responseLimit)await reader.cancel().catch(()=>{});
      reader.releaseLock();
    }
    value=new TextDecoder("utf-8",{fatal:true}).decode(Buffer.concat(chunks));
  }else{
    // Minimal mocks use text(); production native fetch always streams.
    value=await response.text();
    if(Buffer.byteLength(value,"utf8")>responseLimit)throw Error("OUTPUT_OVER_LIMIT");
  }
  let decoded;
  try{decoded=JSON.parse(value);}catch{throw Error("INVALID_WORKER_JSON");}
  if(!isRecord(decoded))throw Error("INVALID_WORKER_SHAPE");
  if(response.status===200){
    // MKK Hyper collects independent vendor sources. Missing sources are
    // explicitly marked partial, not an invalid response. All other routes
    // still reject incomplete results, and MKK partial must be schema-bound.
    const partialMkk=kind==="server-vpn" && payload?.providerId==="mkk-hyper" &&
      decoded.kind==="vpn_catalog" && decoded.providerId==="mkk-hyper" &&
      decoded.isPartial===true && decoded.structuredJson?.complete===false &&
      decoded.structuredJson?.provider==="mkk-hyper" &&
      Array.isArray(decoded.structuredJson?.sources) &&
      decoded.structuredJson.sources.length===4 &&
      decoded.structuredJson.sources.some(x=>x?.status==="ok") &&
      decoded.structuredJson.sources.some(x=>x?.status==="error") &&
      Array.isArray(decoded.warnings) && decoded.warnings.includes("PARTIAL_SOURCE_FAILURE");
    if(decoded.status!=="success" || (decoded.isPartial!==false && !partialMkk) ||
       typeof decoded.rawText!=="string" || !decoded.rawText.length ||
       Buffer.byteLength(decoded.rawText,"utf8")>(isMkk?32*1024*1024:4*1024*1024))
      throw Error("INVALID_WORKER_RESULT");
    if(kind==="server-vpn" && payload?.providerId==="netcol-vpn"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version ||
         !Array.isArray(parsed.Servers) || !parsed.Servers.length ||
         parsed.Servers.some(item=>!isRecord(item) || typeof item.Name!=="string") ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))
        throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="jyfast-vpn-ultra"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || parsed.provider!==payload.providerId || parsed.complete!==true ||
         !isRecord(parsed.catalogs) || Object.keys(parsed.catalogs).sort().join(",")!=="free,premium" ||
         ["free","premium"].some(mode=>!isRecord(parsed.catalogs[mode]) ||
           typeof parsed.catalogs[mode].Version!=="string" || !parsed.catalogs[mode].Version ||
           !Array.isArray(parsed.catalogs[mode].Servers) || !parsed.catalogs[mode].Servers.length ||
           parsed.catalogs[mode].Servers.some(item=>!isRecord(item) || typeof item.Name!=="string")) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))
        throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && ["http-socketclay","http-wakko","onspace-vpn","superflash-vpn","turbomx-vpn"].includes(payload?.providerId)){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || parsed.provider!==payload.providerId || parsed.complete!==true ||
         !isRecord(parsed.catalogs) || Object.keys(parsed.catalogs).sort().join(",")!=="servers,users" ||
         !Array.isArray(parsed.catalogs.servers?.Servers) || !parsed.catalogs.servers.Servers.length ||
         !Array.isArray(parsed.catalogs.users?.Usuarios) || !parsed.catalogs.users.Usuarios.length ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))
        throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="abowaged-vpn"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || parsed.provider!==payload.providerId || parsed.complete!==true ||
         !isRecord(parsed.catalogs) || Object.keys(parsed.catalogs).sort().join(",")!=="servers,udp" ||
         !isRecord(parsed.catalogs.servers) || typeof parsed.catalogs.servers.Version!=="string" ||
         !Array.isArray(parsed.catalogs.servers.Servers) || !Array.isArray(parsed.catalogs.servers.Tweaks) ||
         !(parsed.catalogs.servers.Servers.length || parsed.catalogs.servers.Tweaks.length) ||
         [...parsed.catalogs.servers.Servers,...parsed.catalogs.servers.Tweaks].some(x=>!isRecord(x)) ||
         !Array.isArray(parsed.catalogs.udp) || !parsed.catalogs.udp.length ||
         parsed.catalogs.udp.some(x=>!isRecord(x) || typeof x.UDPserver!=="string" ||
           typeof x.obfs!=="string" || typeof x.auth!=="string") ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="tunneldoom-vpn"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version ||
         !Array.isArray(parsed.Servers) || !parsed.Servers.length ||
         parsed.Servers.some(x=>!isRecord(x) || typeof x.Name!=="string") ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="mnr-tunnel-plus"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version ||
         !Array.isArray(parsed.Servers) || !Array.isArray(parsed.Networks) ||
         [...parsed.Servers,...parsed.Networks].some(x=>!isRecord(x)) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="file" && payload?.format==="stp"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(!isRecord(parsed) || typeof parsed.isPassON!=="boolean" || typeof parsed.MyPass!=="string" ||
         !Number.isInteger(parsed.TunnelType) || JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))
        throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && ["mtm-tunnel-lite","apna-vpn","bd-net-vpn"].includes(payload?.providerId)){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version.length ||
         !Array.isArray(parsed.Free_servers) || !Array.isArray(parsed.Payloads) ||
         ["Free_servers","Premium_servers","Vip_servers","Private_servers","Payloads"].some(name=>
           Object.hasOwn(parsed,name) && (!Array.isArray(parsed[name]) || parsed[name].some(x=>!isRecord(x)))) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && ["aura-net-vpn","wolf-custom-vpn"].includes(payload?.providerId)){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version.length ||
         !Array.isArray(parsed.Servers) || !Array.isArray(parsed.Networks) ||
         parsed.Servers.some(x=>!isRecord(x)) || parsed.Networks.some(x=>!isRecord(x)) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="alfaisal-tunnel-plus"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || typeof parsed.Version!=="string" || !parsed.Version ||
         ["Servers","Networks","SSLNetworks"].some(k=>!Array.isArray(parsed[k])) ||
         !parsed.Servers.length || !(parsed.Networks.length+parsed.SSLNetworks.length) ||
         ["Servers","Networks","SSLNetworks"].some(k=>parsed[k].some(x=>!isRecord(x)||typeof x.Name!=="string")) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && ["enaa-tunnel","7net-vpn","xhypher-tunnel-pro","vip-snipher-pro","izph-vpn-pro"].includes(payload?.providerId)){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || !Object.hasOwn(parsed,"Version") ||
         (payload.providerId==="enaa-tunnel" && (typeof parsed.Version!=="string" || !parsed.Version)) ||
         !Array.isArray(parsed.Servers) || !parsed.Servers.length ||
         !Array.isArray(parsed.Networks) || !parsed.Networks.length ||
         parsed.Servers.some(x=>!isRecord(x)) || parsed.Networks.some(x=>!isRecord(x)) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(kind==="server-vpn" && payload?.providerId==="v2ray-tunnel-plus"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || parsed.provider!==payload.providerId || parsed.complete!==true ||
         !isRecord(parsed.catalogs) || Object.keys(parsed.catalogs).sort().join(",")!=="base64,raw" ||
         ["base64","raw"].some(name=>{
           const doc=parsed.catalogs[name];
           return !isRecord(doc)||doc.encoding!==(name==="raw"?"plain":"base64")||
             typeof doc.text!=="string"||!doc.text.length||!Number.isInteger(doc.count)||doc.count<=0||
             !Array.isArray(doc.profiles)||doc.profiles.length!==doc.count;
         }) || JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson))throw Error("INVALID_WORKER_RESULT");
    }
    if(isMkk){
      // A complete, matching JSON document is mandatory; HTML, logs, partial
      // writes or fabricated structured metadata must not reach the client.
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(!isRecord(parsed) || parsed.provider!=="mkk-hyper" ||
         parsed.sourceCount!==4 || !Array.isArray(parsed.sources) ||
         parsed.sources.length!==4 || !isRecord(decoded.structuredJson) ||
         JSON.stringify(parsed)!==JSON.stringify(decoded.structuredJson) ||
         parsed.complete!==(decoded.isPartial===false) ||
         parsed.successfulSources!==parsed.sources.filter(x=>x?.status==="ok").length ||
         parsed.complete!==(parsed.successfulSources===4) ||
         parsed.successfulSources<1 ||
         parsed.sources.some((x,i)=>x?.name!==["servers","static","subscriptions","legacy-subscriptions"][i] ||
           (x.status!=="ok" && x.status!=="error") ||
           (x.status==="ok" && (!Number.isSafeInteger(x.records) || x.records<0 ||
             !(isRecord(x.data) || Array.isArray(x.data)))) ||
           (x.status==="error" && typeof x.error!=="string")))
        throw Error("INVALID_WORKER_RESULT");
    }
    return jsonReply({...decoded,requestId:randomUUID()},200);
  }
  const code=decoded.error?.code;
  const recognized=Object.hasOwn(ERROR_MESSAGES,code) && !["INTEGRITY_REJECTED","UNAUTHORIZED"].includes(code);
  const safeStatus = [400,401,403,413,422,429,503,504].includes(response.status) ? response.status : 503;
  return failure(recognized?code:"SERVICE_UNAVAILABLE",recognized?safeStatus:503);
}
/** Non-identifying REESE envelope version, extracted only from first four bytes. */
export function rtEnvelopeVersion(encoded){
 if(typeof encoded!=="string"||encoded.length<8)return null;
 let bytes;
 try{bytes=Buffer.from(encoded.slice(0,12),"base64");}catch{return null;}
 const marker=bytes.subarray(0,4).toString("ascii");
 if(["RSE1","RSE2","RSE3","RSE4"].includes(marker))return marker;
 if(bytes.subarray(0,4).equals(Buffer.from([0xa7,0x19,0xd2,0x4c])))return "RSE5";
 if(marker.startsWith("{"))return "JSON";
 return null;
}
export async function decodeRequest(request,kind,options={}) {
  if(!enabled())return notEnabled();
  const cfg=settings();
  let redis,claims,lease=null,telemetry=null,recorded=false,started=null;
  try{
    redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    if(await serviceMaintenanceEnabled(redis,"files"))return failure("SERVICE_MAINTENANCE",503);
    claims=await requireSession(redis,request,cfg);
    if(!claims)return failure("UNAUTHORIZED",401);
    if(claims.rateLimited)return failure("RATE_LIMITED",429);
    const max=kind==="text"?1024*1024:limits.maxJsonBodyBytes;
    const payload=await boundedBody(request,max);
    validatePayload(kind,payload);
    const requestedExport=kind==="file"&&payload.compatibleExport!==undefined;
    let workerPayload=payload,exportUnavailable=null;
    if(requestedExport){
      if(!negotiatesExport(request))return failure("EXPORT_CLIENT_UNSUPPORTED",426);
      let policy=null;
      try{policy=await (options.exportPolicyProvider||exportPolicy)();}
      catch{ /* Export failure must not discard a valid decode. */ }
      if(!policy||!exportAllowed(request,policy)){
        workerPayload={...payload};delete workerPayload.compatibleExport;
        exportUnavailable={status:"unavailable",code:!policy?"EXPORT_POLICY_UNAVAILABLE":
          policy.enabled?"EXPORT_CLIENT_UPDATE_REQUIRED":"EXPORT_DISABLED"};
      }
    }
    const requestId=randomUUID();
    if(!await reserveSlot(redis,claims.jti,requestId))return failure("RATE_LIMITED",429);
    lease=requestId;
    telemetry={
      kind,format:kind==="file"?payload.format:undefined,
      formatVersion:kind==="file"&&payload.format==="rt"?rtEnvelopeVersion(payload.dataBase64):null,
      bytes:kind==="text"?Buffer.byteLength(payload.text,"utf8"):
        payload.dataBase64.length/4*3-
        (payload.dataBase64.endsWith("==")?2:payload.dataBase64.endsWith("=")?1:0),
    };
    started=performance.now();
    let outcome;
    if(kind==="text" && (isHttpCustomReference(payload.text) ||
                        isHttpCustomLegacyReference(payload.text))){
      if(!await providerAllowed("hc-cloud"))return failure("REMOTE_NOT_CONFIGURED",503);
      // Older catalog-aware APKs submit hccloud:// aliases as ordinary text.
      // Resolve exactly to the two pre-approved hosts, never an arbitrary URL.
      // No second fetch is attempted for password/HWID-gated one-use links.
      const source=isHttpCustomLegacyReference(payload.text) ?
        parseHttpCustomLegacyReference(payload.text) : payload.text;
      const data=await importHttpCustomReference(source,options.vendor || {});
      telemetry={kind:"file",format:"hc",bytes:data.length};
      outcome=await fetchWorker("file",{format:"hc",dataBase64:data.toString("base64"),
        ...(payload.credentials?{credentials:payload.credentials}:{})},cfg,options);
    }else if(kind==="text" && payload.text.trim().startsWith("mnrtunneludp://")){
      if(process.env.CLOUD_SERVER_VPN_ENABLED!=="true" || !await providerAllowed("mnr-tunnel-plus"))
        return failure("REMOTE_NOT_CONFIGURED",503);
      // Pasting an explicit MNR reference into Decode requests that one object.
      // No arbitrary URL, storage listing, credential lookup or worker egress.
      const data=await importMnrReference(payload.text,options.vendor || {});
      outcome=await fetchWorker("file",{format:"stp",dataBase64:data.toString("base64")},cfg,options);
    }else outcome=await fetchWorker(kind,workerPayload,cfg,options);
    if(kind==="file"&&outcome.ok){
      const body=await outcome.json();
      if(!requestedExport)delete body.compatibleExport;
      else if(exportUnavailable)body.compatibleExport=exportUnavailable;
      outcome=jsonReply(body,200);
    }
    let errorCode="";
    if(!outcome.ok){
      try{errorCode=(await outcome.clone().json()).error?.code||"";}catch{}
    }
    // The worker always decides if the file requires credentials. An old APK
    // lacks a dialog for the new formats; return only a preexisting localized
    // error code instead of an impossible PASSWORD_REQUIRED interaction.
    // Do not alter successful results, HTTP Custom, or Ultra Custom.
    const legacyCode=legacyCredentialError(request,kind,payload,errorCode);
    const clientOutcome=legacyCode?failure(legacyCode,422):outcome;
    try{await recordWorkerResult(redis,outcome.ok?"success":"failed",{
      ...telemetry,errorCode,latencyMs:performance.now()-started,
      appVersion:request.headers.get("x-spdecode-app-version"),
    });}catch{}
    recorded=true;
    return clientOutcome;
  }catch(error){
    if(telemetry && !recorded && redis && lease){
      try{await recordWorkerResult(redis,"failed",{...telemetry,errorCode:isExternalImportError(error)?error.code:"ENGINE_UNAVAILABLE",
          latencyMs:started===null?null:performance.now()-started,
          appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
    }
    if(isExternalImportError(error))return failure(error.code,error.status);
    if(error?.code==="INPUT_TOO_LARGE")return failure("INPUT_TOO_LARGE",413);
    if(error?.code==="INVALID_BASE64")return failure("INVALID_BASE64",400);
    if(error?.code==="INVALID_CREDENTIALS")return failure("INVALID_CREDENTIALS",400);
    if(error?.code==="INVALID_REQUEST")return failure("INVALID_REQUEST",400);
    return failure("SERVICE_UNAVAILABLE",503);
  }finally{if(redis&&lease){try{await releaseSlot(redis,claims.jti,lease);}catch{}}}
}
export async function challengeRequest(request,options={}) {
  if(!enabled())return notEnabled();
  try {
    const redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    const result=await createChallenge(redis,request);
    if(result.error)return failure(result.error,result.status);
    const policy=await admissionPolicy(redis);
    return jsonReply({apiVersion:"v1",...result,integrityRequired:policy.integrityRequired},201);
  }catch{return failure("SERVICE_UNAVAILABLE",503);}
}
/** Fresh P-256 identity, returned once. No database, telemetry or decoder history. */
export async function npvsIdentityRequest(request,options={}) {
  if(!enabled())return notEnabled();
  let redis,claims,lease;
  try {
    const cfg=settings();
    redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis) || await serviceMaintenanceEnabled(redis,"files"))
      return failure("SERVICE_UNAVAILABLE",503);
    claims=await requireSession(redis,request,cfg);
    if(!claims)return failure("UNAUTHORIZED",401);
    if(claims.rateLimited)return failure("RATE_LIMITED",429);
    const payload=await boundedBody(request,128);
    if(!isRecord(payload) || Object.keys(payload).length!==1 || payload.consent!==true)
      return failure("USER_CONSENT_REQUIRED",400);
    lease=randomUUID();
    if(!await reserveSlot(redis,claims.jti,lease)){lease=null;return failure("RATE_LIMITED",429);}
    if(process.env.WORKER_INTERNAL_URL!=="http://decoder-worker:8787")throw Error("worker origin");
    const response=await (options.fetchImpl||fetch)("http://decoder-worker:8787/internal/v1/npvs/identity",{
      method:"POST",headers:{"Content-Type":"application/json","X-SP-Worker-Token":cfg.workerToken},
      body:'{"consent":true}',redirect:"error",cache:"no-store",signal:AbortSignal.timeout(10000),
    });
    if(response.status!==200)throw Error("identity worker");
    const reader=response.body.getReader();let length=0,chunks=[];
    try{while(true){const item=await reader.read();if(item.done)break;
      length+=item.value.byteLength;if(length>4096)throw Error("identity size");chunks.push(Buffer.from(item.value));
    }}finally{if(length>4096)await reader.cancel().catch(()=>{});reader.releaseLock();}
    const result=JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if(!isRecord(result) || Object.keys(result).join(",")!=="identity")throw Error("identity envelope");
    const key=result.identity;
    if(!isRecord(key) || Object.keys(key).sort().join(",")!=="curve,fingerprint,kind,privateKey,publicKey,schema,source" ||
       key.schema!=="spdecode.npvs.recipient.v1" || key.source!=="generated" || key.kind!=="keypair" || key.curve!=="P-256" ||
       !/^[A-Za-z0-9_-]{100,512}$/.test(key.privateKey) || !/^[A-Za-z0-9_-]{44}$/.test(key.publicKey))throw Error("identity schema");
    const privateKey=createPrivateKey({key:Buffer.from(key.privateKey,"base64url"),format:"der",type:"pkcs8"});
    if(privateKey.asymmetricKeyDetails?.namedCurve!=="prime256v1")throw Error("identity curve");
    const jwk=createPublicKey(privateKey).export({format:"jwk"});
    const publicKey=ECDH.convertKey(Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,"base64url"),Buffer.from(jwk.y,"base64url")]),"prime256v1",undefined,undefined,"compressed");
    if(publicKey.toString("base64url")!==key.publicKey || createHash("sha256").update(publicKey).digest("hex")!==key.fingerprint)
      throw Error("identity mismatch");
    return jsonReply({identity:key},201);
  }catch(error){
    if(error?.code==="INVALID_REQUEST")return failure("INVALID_REQUEST",400);
    if(error?.code==="INPUT_TOO_LARGE")return failure("INPUT_TOO_LARGE",413);
    return failure("SERVICE_UNAVAILABLE",503);
  }
  finally{if(redis&&lease&&claims){try{await releaseSlot(redis,claims.jti,lease);}catch{}}}
}
export async function sessionRequest(request,options={}) {
  if(!enabled())return notEnabled();
  try{
    const redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    const data=await boundedBody(request,19000);
    const policy=await admissionPolicy(redis);
    const result=await issueSession(redis,request,data,settings(),options.verifyIntegrity,policy);
    if(result.error)return failure(result.error,result.status);
    return jsonReply({apiVersion:"v1",...result},201);
  }catch(error){
    if(error?.code==="INVALID_REQUEST")return failure("INVALID_REQUEST",400);
    if(error?.code==="INPUT_TOO_LARGE")return failure("INPUT_TOO_LARGE",413);
    return failure("SERVICE_UNAVAILABLE",503);
  }
}
export async function qaSessionRequest(request,options={}) {
  if(!enabled())return notEnabled();
  if(!settings().qaActive)return failure("QA_DISABLED",403);
  try{
    const redis=await (options.storeProvider||store)();
    if(await maintenanceEnabled(redis))return failure("SERVICE_UNAVAILABLE",503);
    const data=await boundedBody(request,512);
    const result=await issueQaSession(redis,request,data,settings());
    if(result.error)return failure(result.error,result.status);
    return jsonReply({apiVersion:"v1",...result},201);
  }catch(error){
    return failure(error?.code==="INVALID_REQUEST"?"INVALID_REQUEST":"SERVICE_UNAVAILABLE",
      error?.code==="INVALID_REQUEST"?400:503);
  }
}
export async function capabilitiesRequest(options={}) {
  if(!enabled())return notEnabled();
  try{
    const cfg=settings();
    if(process.env.WORKER_INTERNAL_URL!=="http://decoder-worker:8787")throw Error("WORKER_NOT_CONFIGURED");
    const response=await (options.fetchImpl||fetch)("http://decoder-worker:8787/internal/v1/capabilities",{
      headers:{"X-SP-Worker-Token":cfg.workerToken},
      cache:"no-store",redirect:"error",signal:AbortSignal.timeout(4000),
    });
    if(!response.ok)throw Error("WORKER_UNAVAILABLE");
    const value=await response.json();
    if(!Array.isArray(value.fileRoutes)||value.fileRoutes.length!==240 ||
       value.exporterCertified!==false)throw Error("INVALID_CAPABILITIES");
    return jsonReply({
      apiVersion:"v1",status:"operational",phase:"C3",decodingEnabled:true,
      enabledFormats:value.fileRoutes,
      fileDecoderCatalog:{catalogRoutes:239,additionalSolidRoute:1,exporterVersionsCertified:0},
      textDecodingEnabled:Boolean(value.textDecodingEnabled),
      cloudImportsEnabled:ehiConfigured(),nurCatalogEnabled:Boolean(value.nurCatalogEnabled),
      nurRemoteEnabled:nurConfigured(),
      note:"Rutas de ejecución disponibles; certificación de versiones reales pendiente.",
    });
  }catch{return failure("SERVICE_UNAVAILABLE",503);}
}
export async function readinessRequest(options={}) {
  if(!enabled())return jsonReply({apiVersion:"v1",status:"not_ready",reason:"CLOUD_SECURITY_GATE_DISABLED"},503);
  if(process.env.CLOUD_LEGACY_API_ENABLED==="false" && !v2Settings().configured)
    return jsonReply({apiVersion:"v2",status:"not_ready",reason:"CLOUD_SECURITY_GATE_DISABLED"},503);
  try {
    const redis=await (options.storeProvider||store)();
    if((await redis.ping())!=="PONG")throw Error("REDIS_OFFLINE");
    if(await maintenanceEnabled(redis))throw Error("MAINTENANCE");
    if(process.env.WORKER_INTERNAL_URL!=="http://decoder-worker:8787")throw Error("WORKER_NOT_CONFIGURED");
    const worker=await (options.fetchImpl||fetch)("http://decoder-worker:8787/ready",{
      cache:"no-store",signal:AbortSignal.timeout(4000),redirect:"error",
    });
    if(!worker.ok)throw Error("WORKER_NOT_READY");
    return jsonReply({apiVersion:"v1",status:"ready",note:"Service configured; individual decoding results are not exporter-certified."});
  }catch{return jsonReply({apiVersion:"v1",status:"not_ready",reason:"CLOUD_SECURITY_DEPENDENCY_UNAVAILABLE"},503);}
}
