/** CI-only download observation. Never decrypt or export response bodies. */
import {readFile,writeFile,mkdir,appendFile} from "node:fs/promises";
import {createHash} from "node:crypto";
import {resolve} from "node:path";
import {fileURLToPath,pathToFileURL} from "node:url";
import {Worker,isMainThread,parentPort,workerData} from "node:worker_threads";
import https from "node:https";
import http from "node:http";
import {providerIds,downloadVpnCatalog,mkkSourceIds,VpnProviderError} from "../../cloud/web/lib/server-vpn-provider.mjs";
import {SERVER_VPN_METHODS} from "../../cloud/web/lib/server-vpn-catalog.mjs";
import {downloadNur,ExternalImportError} from "../../cloud/web/lib/c35-provider.mjs";

const ROOT=fileURLToPath(new URL("../../",import.meta.url));
const SHA=/^[a-f0-9]{64}$/;
const ID=/^[a-z0-9][a-z0-9-]{0,63}$/;
const KINDS=new Set(["JSON_OBJECT","JSON_ARRAY","JSON_SCALAR","BASE64_TEXT","HEX_TEXT","TEXT","BINARY"]);
const SCOPE="TRANSPORT_ONLY_NO_DECRYPTION";
const hash=value=>createHash("sha256").update(value).digest("hex");
const keyOf=item=>item.id+"/"+item.source;
const MAX_BYTES=16*1024*1024;
const WARNINGS={
  REMOTE_ROUTE_NOT_CONFIGURED:"Sin ruta remota habilitada en el repositorio; revisión pendiente.",
  REMOTE_NOT_CONFIGURED:"Falta configuración o credenciales válidas en Actions; descarga no comprobada.",
  REMOTE_NETWORK_DENIED:"DNS, destino o red rechazados por el descargador; revisar acceso.",
  REMOTE_PROVIDER_UNAVAILABLE:"La fuente no respondió correctamente; revisar HTTP, red o cambios del proveedor.",
  REMOTE_RESPONSE_INVALID:"Respuesta vacía, inesperada o no utilizable como descarga de catálogo.",
  REMOTE_TOO_LARGE:"La respuesta superó el límite del descargador.",
  REMOTE_TIMEOUT:"La comprobación agotó su plazo; disponibilidad no confirmada.",
  HTML_OR_XML_RESPONSE:"Se recibió una página HTML/XML; revisar la fuente del catálogo.",
  REMOTE_ERROR_DOCUMENT:"Se recibió un documento de error en lugar del catálogo.",
  EMPTY_RESPONSE:"La descarga no contiene datos de catálogo.",
  PAYLOAD_FORMAT_CHANGED:"Cambió el contenedor o la estructura respecto a la referencia; revisar posible actualización.",
  INTERNAL_PROBE_FAILURE:"Falló el comprobador; consultar sus pruebas antes de atribuirlo al proveedor.",
};

/** Extract only source identifiers; no copied URLs and no eval.
 * Fail visibly on a changed declaration grammar instead of omitting sources.
 */
export function sourceMap(source,ids=providerIds()){
  const match=/const PAIRED_SOURCES\s*=\s*Object\.freeze\(\{([^}]+)\}\);/.exec(source);
  if(!match)throw Error("SOURCE_INVENTORY_UNRECOGNIZED");
  const result=new Map(ids.map(id=>[id,["servers"]]));
  const pairs=[...match[1].matchAll(/"([a-z0-9-]+)"\s*:\s*([A-Z][A-Z0-9_]*_SOURCES)/g)];
  const residue=match[1].replace(/"([a-z0-9-]+)"\s*:\s*([A-Z][A-Z0-9_]*_SOURCES)/g,"").replace(/[\s,]/g,"");
  if(!pairs.length||residue)throw Error("SOURCE_INVENTORY_UNRECOGNIZED");
  for(const [,id,variable] of pairs){
    if(!result.has(id))throw Error("UNKNOWN_PAIRED_PROVIDER");
    const declaration=new RegExp("const "+variable+"\\s*=\\s*Object\\.freeze\\(\\{([\\s\\S]*?)\\}\\);").exec(source);
    if(!declaration)throw Error("MISSING_SOURCE_DECLARATION");
    const pattern=/(?:^|,)\s*(?:"([a-z0-9-]+)"|([a-z0-9-]+))\s*:\s*"[^"\n]+"\s*(?=,|$)/g;
    const parts=[...declaration[1].matchAll(pattern)];
    const rest=declaration[1].replace(pattern,"").replace(/[\s,]/g,"");
    const names=parts.map(m=>m[1]||m[2]);
    if(!names.length||rest||new Set(names).size!==names.length)throw Error("SOURCE_KEYS_UNRECOGNIZED");
    result.set(id,names);
  }
  if(result.has("mkk-hyper"))result.set("mkk-hyper",mkkSourceIds());
  return result;
}
export function buildPlan(source,roster=SERVER_VPN_METHODS,ids=providerIds()){
  const sources=sourceMap(source,ids),seen=new Set(),plan=[];
  for(const item of roster){
    if(!ID.test(item.id)||seen.has(item.id))throw Error("INVALID_CATALOG_INVENTORY");
    seen.add(item.id);
    if(sources.has(item.id)){
      for(const source of sources.get(item.id))plan.push({...item,source,route:"broker"});
    }else if(item.id==="nur-tunnel"){
      plan.push({...item,source:"servers",route:"nur"});
    }else{
      plan.push({...item,source:"unavailable",route:"unconfigured"});
    }
  }
  if(ids.some(id=>!seen.has(id)))throw Error("BROKER_PROVIDER_NOT_IN_ROSTER");
  return plan;
}
function shape(value){
  if(value===null)return "null";
  if(Array.isArray(value))return ["array"]; // Record counts and values change normally.
  if(typeof value==="object")return ["object",Object.keys(value).sort().map(key=>
    [key,value[key]===null?"null":Array.isArray(value[key])?"array":typeof value[key]])];
  return typeof value;
}
export function inspectPayload(input,id=""){
  if(!Buffer.isBuffer(input)||!input.length)return {status:"WARN",code:"EMPTY_RESPONSE"};
  if(input.length>MAX_BYTES)return {status:"WARN",code:"REMOTE_TOO_LARGE"};
  let bytes=input;
  if(id==="http-conexion"){
    // The broker wrapper includes a password. Hash ONLY the original catalog.
    let wrapper;
    try{wrapper=JSON.parse(bytes.toString("utf8"));}catch{return {status:"WARN",code:"REMOTE_RESPONSE_INVALID"};}
    const encoded=wrapper?.catalogBase64;
    if(wrapper?.kind!=="spdecode-http-conexion-config-v1"||typeof encoded!=="string"||
       !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)||encoded.length%4!==0)
      return {status:"WARN",code:"REMOTE_RESPONSE_INVALID"};
    bytes=Buffer.from(encoded,"base64");
    if(bytes.toString("base64")!==encoded||!bytes.length||bytes.length>MAX_BYTES)
      return {status:"WARN",code:"REMOTE_RESPONSE_INVALID"};
  }
  let text=null;
  try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes).replace(/^\uFEFF/,"").trim();}catch{}
  if(text==="")return {status:"WARN",code:"EMPTY_RESPONSE"};
  if(text?.startsWith("<"))return {status:"WARN",code:"HTML_OR_XML_RESPONSE"};
  let kind="BINARY",signature="BINARY";
  if(text!==null){
    let value,parsed=false;
    try{value=JSON.parse(text);parsed=true;}catch{}
    if(parsed){
      if(value&&typeof value==="object"&&!Array.isArray(value)&&
         (value.success===false||value.status==="error"||
          (typeof value.error==="string"&&Object.keys(value).every(k=>
            ["error","message","status","code","success"].includes(k)))))
        return {status:"WARN",code:"REMOTE_ERROR_DOCUMENT"};
      kind=Array.isArray(value)?"JSON_ARRAY":value!==null&&typeof value==="object"?"JSON_OBJECT":"JSON_SCALAR";
      signature=JSON.stringify(shape(value));
    }else{
      if(text.length<1024&&/^(?:not found|404|403|unauthorized|forbidden|access denied|site unavailable|service unavailable|maintenance|invalid (?:request|hash|key|signature))(?:[\s.!:]|$)/i.test(text))
        return {status:"WARN",code:"REMOTE_ERROR_DOCUMENT"};
      const compact=text.replace(/\s/g,"");
      kind=compact.length>=32&&compact.length%2===0&&/^[a-f0-9]+$/i.test(compact)?"HEX_TEXT":
        compact.length>=32&&compact.length%4===0&&/^[A-Za-z0-9+/]+={0,2}$/.test(compact)?"BASE64_TEXT":"TEXT";
      signature=kind;
    }
  }
  return {status:"OK",code:"DOWNLOAD_OK",bytes:bytes.length,payloadKind:kind,
    bodySha256:hash(bytes),shapeSha256:hash(signature),decryptionPerformed:false};
}
export function validateBaseline(value){
  if(!value||value.schemaVersion!==1||value.scope!==SCOPE||
     !value.entries||typeof value.entries!=="object"||Array.isArray(value.entries))
    throw Error("INVALID_DOWNLOAD_BASELINE");
  for(const [key,item] of Object.entries(value.entries)){
    if(!/^[a-z0-9-]+\/[a-z0-9-]+$/.test(key)||!KINDS.has(item?.payloadKind)||
       !SHA.test(item?.bodySha256)||!SHA.test(item?.shapeSha256)||
       Object.keys(item).sort().join(",")!=="bodySha256,payloadKind,shapeSha256")
      throw Error("INVALID_DOWNLOAD_BASELINE");
  }
  return value;
}
export function compareResult(observation,reference){
  if(observation.status!=="OK")return observation;
  if(!reference)return {...observation,baselineAvailable:false,contentChanged:null,formatChanged:null};
  const changed=observation.payloadKind!==reference.payloadKind||observation.shapeSha256!==reference.shapeSha256;
  const contentChanged=observation.bodySha256!==reference.bodySha256;
  return {...observation,baselineAvailable:true,contentChanged,formatChanged:changed,
    status:changed?"WARN":"OK",
    code:changed?"PAYLOAD_FORMAT_CHANGED":contentChanged?"CATALOG_CONTENT_CHANGED":"DOWNLOAD_OK"};
}
export async function observeDownload(item){
  if(item.route==="unconfigured")return {status:"WARN",code:"REMOTE_ROUTE_NOT_CONFIGURED",httpStatuses:[]};
  const statuses=[],originals=[];
  // Observe status codes only. Never retain URLs, headers or bodies.
  for(const transport of [https,http]){
    const original=transport.request;
    originals.push([transport,original]);
    transport.request=function(...args){
      const at=args.length-1;
      if(typeof args[at]==="function"){
        const callback=args[at];
        args[at]=function(response){
          if(Number.isInteger(response.statusCode)&&statuses.length<24)statuses.push(response.statusCode);
          return callback(response);
        };
      }
      return original.apply(this,args);
    };
  }
  try{
    const bytes=item.route==="nur"?await downloadNur():await downloadVpnCatalog(item.id,item.source);
    return {...inspectPayload(bytes,item.id),httpStatuses:statuses};
  }catch(error){
    if(error instanceof VpnProviderError||error instanceof ExternalImportError)
      return {status:"WARN",code:Object.hasOwn(WARNINGS,error.code)?error.code:"REMOTE_RESPONSE_INVALID",httpStatuses:statuses};
    return {status:"ERROR",code:"INTERNAL_PROBE_FAILURE",httpStatuses:statuses};
  }finally{
    for(const [transport,original] of originals)transport.request=original;
  }
}
export function probeInWorker(item,{timeoutMs=45000}={}){
  if(item.route==="unconfigured")return Promise.resolve({status:"WARN",code:"REMOTE_ROUTE_NOT_CONFIGURED",httpStatuses:[]});
  return new Promise(resolvePromise=>{
    const worker=new Worker(new URL(import.meta.url),{workerData:{catalogDownloadProbe:true,item},
      stdout:true,stderr:true,resourceLimits:{maxOldGenerationSizeMb:192}});
    worker.stdout.resume();worker.stderr.resume();
    let settled=false;
    const finish=result=>{
      if(settled)return;settled=true;
      clearTimeout(timer);
      worker.terminate().finally(()=>resolvePromise(result));
    };
    const timer=setTimeout(()=>finish({status:"WARN",code:"REMOTE_TIMEOUT",httpStatuses:[]}),timeoutMs);
    worker.once("message",finish);
    worker.once("error",()=>finish({status:"ERROR",code:"INTERNAL_PROBE_FAILURE",httpStatuses:[]}));
    worker.once("exit",()=>{if(!settled)finish({status:"ERROR",code:"INTERNAL_PROBE_FAILURE",httpStatuses:[]});});
  });
}
export async function runChecks(plan,baseline,{probe=probeInWorker,concurrency=4}={}){
  if(!Number.isInteger(concurrency)||concurrency<1||concurrency>8)throw Error("INVALID_CONCURRENCY");
  let next=0;
  const results=new Array(plan.length);
  await Promise.all(Array.from({length:Math.min(plan.length,concurrency)},async()=>{
    for(;;){
      const index=next++;
      if(index>=plan.length)break;
      const item=plan[index],started=Date.now();
      const observation=compareResult(await probe(item),baseline.entries[keyOf(item)]);
      results[index]={id:item.id,name:item.name,source:item.source,...observation,durationMs:Date.now()-started};
    }
  }));
  return {schemaVersion:1,scope:SCOPE,observedAt:new Date().toISOString(),
    providerCount:new Set(plan.map(p=>p.id)).size,sourceCount:plan.length,
    ok:results.filter(r=>r.status==="OK").length,
    warnings:results.filter(r=>r.status==="WARN").length,
    internalErrors:results.filter(r=>r.status==="ERROR").length,
    decryptionPerformed:false,decoderCompatibility:"NOT_TESTED",results};
}
const cell=value=>String(value).replace(/[|\r\n\x60]/g," ");
export function markdown(report){
  return [
    "# Descarga de catálogos","",
    report.providerCount+" proveedores · "+report.sourceCount+" fuentes · "+report.ok+" descargas válidas · "+
      report.warnings+" advertencias · "+report.internalErrors+" errores internos.","",
    "Solo descarga. Un cambio normal de contenido no es un método roto. La compatibilidad del descifrador no se comprobó.",
    "Los avisos de red, configuración o formato requieren revisión; no afirman que el método murió.","",
    "| Proveedor | Fuente | Resultado | HTTP | Bytes | Observación |",
    "| --- | --- | --- | --- | ---: | --- |",
    ...report.results.map(r=>"| "+[
      cell(r.name),cell(r.source),r.status==="OK"?"✅ Descargado":r.status==="WARN"?"⚠️ Advertencia":"❌ Comprobador",
      (r.httpStatuses||[]).join(", ")||"—",r.bytes??"—",cell(WARNINGS[r.code]||
        (r.code==="CATALOG_CONTENT_CHANGED"?"Contenido actualizado; formato estable.":
          r.baselineAvailable===false?"Descarga válida; sin referencia de formato todavía.":"Descarga válida.")),
    ].join(" | ")+" |"),"",
    "No se guardaron respuestas, contraseñas, tokens, URLs ni catálogos descifrados.","",
  ].join("\n");
}
export async function main(args=process.argv.slice(2)){
  const flags=new Map();
  for(let i=0;i<args.length;i+=2){
    if(!["--out","--baseline","--provider"].includes(args[i])||!args[i+1]||flags.has(args[i]))
      throw Error("INVALID_ARGUMENTS");
    flags.set(args[i],args[i+1]);
  }
  const source=await readFile(new URL("../../cloud/web/lib/server-vpn-provider.mjs",import.meta.url),"utf8");
  let plan=buildPlan(source);
  const selected=flags.get("--provider")||process.env.CATALOG_DOWNLOAD_PROVIDER||"all";
  if(selected!=="all"){
    if(!ID.test(selected)||!plan.some(p=>p.id===selected))throw Error("UNKNOWN_PROVIDER_SELECTION");
    plan=plan.filter(p=>p.id===selected);
  }
  const baseline=validateBaseline(JSON.parse(await readFile(resolve(ROOT,flags.get("--baseline")||
    "scripts/ci/catalog-download-baseline.json"),"utf8")));
  const output=resolve(flags.get("--out")||"catalog-download-results");
  const report=await runChecks(plan,baseline);
  const summary=markdown(report),candidates={schemaVersion:1,scope:SCOPE,entries:{}};
  for(const item of report.results){
    if(item.status==="OK")candidates.entries[keyOf(item)]=Object.fromEntries(
      ["payloadKind","bodySha256","shapeSha256"].map(k=>[k,item[k]]));
    console.log("CATALOG_DOWNLOAD_RESULT "+JSON.stringify(item));
    if(item.status==="WARN"&&process.env.GITHUB_ACTIONS==="true")
      console.log("::warning title=Catálogo "+item.id+" ("+item.source+")::"+WARNINGS[item.code]);
  }
  await mkdir(output,{recursive:true});
  await writeFile(resolve(output,"report.json"),JSON.stringify(report,null,2)+"\n",{mode:0o600});
  await writeFile(resolve(output,"summary.md"),summary,{mode:0o600});
  await writeFile(resolve(output,"baseline-candidates.json"),JSON.stringify(candidates,null,2)+"\n",{mode:0o600});
  if(process.env.GITHUB_STEP_SUMMARY)await appendFile(process.env.GITHUB_STEP_SUMMARY,summary);
  console.log("CATALOG_DOWNLOAD_TOTAL "+JSON.stringify({
    providers:report.providerCount,sources:report.sourceCount,ok:report.ok,warnings:report.warnings,
    internalErrors:report.internalErrors,decryptionPerformed:false}));
  // External outages remain warnings; broken CI code remains an actual failure.
  if(report.internalErrors)process.exitCode=1;
  return report;
}
if(!isMainThread&&workerData?.catalogDownloadProbe){
  parentPort.postMessage(await observeDownload(workerData.item));
}else if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  main().catch(()=>{console.error("CATALOG_DOWNLOAD_CHECK_INTERNAL_FAILURE");process.exitCode=1;});
}

