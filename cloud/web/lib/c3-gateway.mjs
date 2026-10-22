import { randomUUID } from "node:crypto";
import { settings, limits } from "./c3-config.mjs";
import { store, reserveSlot, releaseSlot } from "./c3-store.mjs";
import { createChallenge, issueSession, issueQaSession, requireSession } from "./c3-session.mjs";
import { jsonReply, unavailable } from "./responses.mjs";
import { ehiConfigured, nurConfigured } from "./c35-provider.mjs";
import { maintenanceEnabled, serviceMaintenanceEnabled, recordWorkerResult } from "./c6-ops-store.mjs";
import {admissionPolicy} from "./c11-play-admission.mjs";

const ERROR_MESSAGES = Object.freeze({
  INVALID_REQUEST:"Solicitud inválida.",
  UNAUTHORIZED:"Sesión no autorizada o caducada.",
  RATE_LIMITED:"Límite de solicitudes alcanzado.",
  INPUT_TOO_LARGE:"Archivo o texto demasiado grande.",
  UNSUPPORTED_FORMAT:"Formato no reconocido por el servidor.",
  INVALID_INPUT:"Entrada inválida.",
  INVALID_BASE64:"Archivo Base64 inválido.",
  INVALID_CREDENTIALS:"Credenciales inválidas.",
  PASSWORD_REQUIRED:"Se requiere contraseña.",
  HWID_REQUIRED:"Se requiere HWID.",
  HWID_PASSWORD_REQUIRED:"Se requieren contraseña y HWID.",
  AUTH_FAILED:"No se pudo autenticar el archivo.",
  DECODE_FAILED:"No se pudo descifrar el archivo.",
  NPVS_PROTECTION_UNSUPPORTED:"Este archivo NPVS utiliza una protección por contraseña o clave que aún no está implementada.",
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
    if (Object.keys(payload).some(x=>!["format","dataBase64","credentials"].includes(x)) ||
        typeof payload.format!=="string" || (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(payload.format) && payload.format!=="fɴ"))
      throw Object.assign(new Error("format"),{code:"INVALID_REQUEST"});
    if (payload.credentials!==undefined){
      const allowed=payload.format==="hc"?["password","hwid"]:["tut","ua"].includes(payload.format)?["password"]:null;
      if (!allowed || !isRecord(payload.credentials) ||
          Object.keys(payload.credentials).some(k=>!allowed.includes(k)))
        throw Object.assign(new Error("credentials"),{code:"INVALID_CREDENTIALS"});
      for(const [key,max] of [["password",4096],["hwid",128]]){
        const value=payload.credentials[key];
        if(value!==undefined && (typeof value!=="string" || !value.length || value.length>max))
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
      if(!payload.text.trim().toLowerCase().startsWith("ua://") ||
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
    method:"POST",signal:AbortSignal.timeout((kind==="catalog"||kind==="server-vpn")?135000:25000),
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
    if(kind==="server-vpn" && payload?.providerId==="xhypher-tunnel-pro"){
      let parsed;
      try{parsed=JSON.parse(decoded.rawText);}catch{throw Error("INVALID_WORKER_RESULT");}
      if(decoded.kind!=="vpn_catalog" || decoded.providerId!==payload.providerId ||
         !isRecord(parsed) || !Object.hasOwn(parsed,"Version") ||
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
    const outcome=await fetchWorker(kind,payload,cfg,options);
    let errorCode="";
    if(!outcome.ok){
      try{errorCode=(await outcome.clone().json()).error?.code||"";}catch{}
    }
    try{await recordWorkerResult(redis,outcome.ok?"success":"failed",{
      ...telemetry,errorCode,latencyMs:performance.now()-started,
      appVersion:request.headers.get("x-spdecode-app-version"),
    });}catch{}
    recorded=true;
    return outcome;
  }catch(error){
    if(telemetry && !recorded && redis && lease){
      try{await recordWorkerResult(redis,"failed",{...telemetry,errorCode:"ENGINE_UNAVAILABLE",
          latencyMs:started===null?null:performance.now()-started,
          appVersion:request.headers.get("x-spdecode-app-version")});}catch{}
    }
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
