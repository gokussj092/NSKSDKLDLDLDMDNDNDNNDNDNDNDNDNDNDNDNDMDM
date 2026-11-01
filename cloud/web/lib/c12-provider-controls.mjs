/** Persistent, operator-controlled provider availability.
 * Store ONLY fixed provider IDs, Boolean disabled switches and a monotonic
 * catalog version in the dedicated isolated Docker volume. Never store URLs,
 * passwords, decoded payloads, device identifiers or admin sessions here.
 */
import {readFile,open,rename,unlink,access} from "node:fs/promises";
import {join} from "node:path";
import {randomUUID,createHash} from "node:crypto";
import {providerIds,providerEnabled} from "./server-vpn-provider.mjs";
import {ehiConfigured,nurConfigured} from "./c35-provider.mjs";
import {activeCatalogVersion,catalog} from "./server-vpn-catalog.mjs";

const ROOT="/app/provider-control";
const IDS=Object.freeze(["ehi-cloud","hc-cloud","nur-tunnel",...providerIds()]);
export const PUBLIC_PROVIDER_IDS=IDS;
const LABELS=Object.freeze({
  "ha-tunnel-plus":"HA Tunnel Plus",
  "ultra-tunnel":"Ultra Tunnel",
  "mm-tunnel":"MM Tunnel",
  "zig-tunnel":"ZiG Tunnel",
  "enaa-tunnel":"Enaa Tunnel",
  "alfaisal-tunnel-plus":"ALFAISAL Tunnel+",
  "izph-vpn-pro":"IZPH VPN PRO",
  "vip-snipher-pro":"VIP Snipher Pro",
  "netcol-vpn":"Netcol VPN",
  "wolf-custom-vpn":"Wolf Custom VPN",
  "jyfast-vpn-ultra":"JyFast VPN Ultra",
  "tunneldoom-vpn":"TunnelDOOM VPN",
  "mtm-tunnel-lite":"MTM Tunnel Lite",
  "mnr-tunnel-plus":"MNR TUNNEL PLUS",
  "bd-net-vpn":"BD NET VPN",
  "aura-net-vpn":"Aura Net VPN",
  "apna-vpn":"APNA VPN",
  "any-vpn":"ANY VPN",
  "speicers-pro-vpn":"Speicers Pro VPN",
  "tx-tunnel":"Tx Tunnel",
  "abowaged-vpn":"AboWaged VPN",
  "7net-vpn":"7NET VPN",
  "xhypher-tunnel-pro":"Xhypher Tunnel Pro",
  "turbomx-vpn":"TurboMX VPN",
  "superflash-vpn":"SuperFlash VPN",
  "rmp-tunnel-pro":"RMP TUNNEL PRO",
  "rjc-tunnel-pro":"RJC TUNNEL PRO",
  "onspace-vpn":"OnSpace VPN",
  "mx-tunnel-pro":"Mx Tunnel PRO",
  "megatunnel":"MegaTunnel",
  "http-internet-infinito":"HTTP Internet Infinito",
  "freedom-vpn":"FreedomVPN",
  "focus-vpn-cloud":"Focus VPN Cloud",
  "v2ray-tunnel-plus":"V2ray Tunnel Plus",
  "ehi-cloud":"HTTP Injector Cloud",
  "hc-cloud":"HTTP Custom Cloud",
  "nur-tunnel":"Servidores VPN",
  "http-wakko":"HTTP Wakko",
  "http-socketclay":"HTTP SocketClay",
  "tunneltweak":"Tunneltweak",
  "http-jireh":"HTTP Jireh",
  "http-fenixvpn":"HTTP FenixVPN",
  "austroplus-vpn":"AustroPlus VPN",
  "ac-tunnel-vpn":"AC TUNNEL VPN",
  "24clan-green":"24clan VPN Green",
  "hx-tunnel":"HX Tunnel VPN",
  "mkk-hyper":"MKK Hyper VPN",
  "ksh-vpn":"KSH VPN",
  "my-tunnel-proxy":"My Tunnel Proxy",
  "robust-tunnel":"Robust Tunnel VPN",
  "trv-tunnel":"TRV TUNNEL",
  "4u-tunnel-lite":"4U TUNNEL LITE",
});
const empty=()=>({version:0,disabled:[]});
let rosterFingerprint=null;
// Include the release floor so enabling a previously visible offline card also
// invalidates cached availability, even when IDs/names/icons do not change.
// The version only advances for a changed deployment's actual catalog metadata.
function catalogFingerprint(){
  if(rosterFingerprint)return rosterFingerprint;
  const snapshot=catalog({version:1,availability:{}});
  const records=snapshot.apps.map(({id,name,iconSha256,iconMimeType})=>
    ({id,name,iconSha256,iconMimeType}));
  // Include format metadata, so changes invalidate old versioned Android caches.
  rosterFingerprint=createHash("sha256").update(JSON.stringify({
    releaseVersion:activeCatalogVersion({}),records,
    formatsSchemaVersion:snapshot.formatsSchemaVersion,
    formatDetection:snapshot.formatDetection,
    formats:snapshot.formats,
    onlineReferenceFormats:snapshot.onlineReferenceFormats,
  })).digest("hex");
  return rosterFingerprint;
}
const valid=s=>s && typeof s==="object" && !Array.isArray(s) &&
  Number.isSafeInteger(s.version) && s.version>=0 && s.version<1_000_000_000 &&
  Array.isArray(s.disabled) && s.disabled.length<=IDS.length &&
  s.disabled.every(x=>typeof x==="string" && IDS.includes(x)) &&
  new Set(s.disabled).size===s.disabled.length &&
  (s.catalogFingerprint===undefined ||
    (typeof s.catalogFingerprint==="string" && /^[a-f0-9]{64}$/.test(s.catalogFingerprint)));

export async function loadProviderState(root=ROOT){
  const STATE=join(root,"switches.json");
  let raw;
  try{raw=await readFile(STATE,"utf8");}
  catch(e){if(e?.code==="ENOENT")return empty();throw e;}
  if(raw.length>8192)throw Error("PROVIDER_STATE_INVALID");
  let state;
  try{state=JSON.parse(raw);}catch{throw Error("PROVIDER_STATE_INVALID");}
  if(!valid(state))throw Error("PROVIDER_STATE_INVALID");
  return state;
}
/** Reconcile on-disk state with the deployed roster/icon fingerprint once.
 * A previous admin toggle may have raised the cached version far above the
 * static release number. Never regress that version or overwrite disabled IDs.
 * The control volume is mounted only in production: file-based unit tests
 * without a volume continue using the static release baseline.
 */
export async function synchronizeCatalogVersion(env=process.env,{root=ROOT}={}){
  try{await access(root);}
  catch(error){
    if(error?.code==="ENOENT")return loadProviderState(root);
    throw error;
  }
  const fingerprint=catalogFingerprint();
  const previous=await loadProviderState(root);
  if(previous.catalogFingerprint===fingerprint)return previous;
  return locked(async()=>{
    const state=await loadProviderState(root);
    if(state.catalogFingerprint===fingerprint)return state;
    const floor=Math.floor(Date.now()/1000)-1_577_836_800;
    const next=Math.max(state.version,activeCatalogVersion(env),floor)+1;
    if(next>=1_000_000_000)throw Error("CATALOG_VERSION_EXHAUSTED");
    const updated={...state,version:next,catalogFingerprint:fingerprint};
    const file=join(root,"switches.json");
    const tmp=join(root,".switches-"+randomUUID());
    const handle=await open(tmp,"wx",0o600);
    try{await handle.writeFile(JSON.stringify(updated)+"\n","utf8");await handle.sync();}
    finally{await handle.close();}
    try{await rename(tmp,file);}
    catch(error){await unlink(tmp).catch(()=>{});throw error;}
    return updated;
  },root);
}
export function providerPrerequisite(id,env=process.env){
  if(!IDS.includes(id))throw Error("INVALID_PROVIDER");
  if(env.CLOUD_API_ENABLED!=="true")return false;
  if(id==="hc-cloud")return env.CLOUD_HTTP_CUSTOM_IMPORT_ENABLED!=="false";
  if(id==="ehi-cloud")return ehiConfigured(env);
  if(id==="nur-tunnel")return nurConfigured(env);
  return providerEnabled(id,env);
}
export function providerEffective(id,state,env=process.env){
  if(!valid(state))throw Error("PROVIDER_STATE_INVALID");
  return providerPrerequisite(id,env) && !state.disabled.includes(id);
}
export async function providerAllowed(id,env=process.env,{root=ROOT}={}){
  return providerEffective(id,await loadProviderState(root),env);
}
export async function providerOverview(env=process.env,{root=ROOT,syncCatalog=false}={}){
  const state=syncCatalog?await synchronizeCatalogVersion(env,{root}):await loadProviderState(root);
  return {
    catalogVersion:Math.max(activeCatalogVersion(env),state.version),
    providers:IDS.map(id=>({
      id,name:LABELS[id],configured:providerPrerequisite(id,env),
      enabled:providerEffective(id,state,env),
    })),
  };
}
// Cross-request lock, needed because Next.js splits API routes into bundles.
// A crashed writer may leave a lock; only the owner removes it, or operator cleans it.
async function locked(callback,root=ROOT){
  const LOCK=join(root,"switches.lock");
  let file;
  for(let i=0;i<15;i++){
    try{file=await open(LOCK,"wx",0o600);break;}
    catch(e){
      if(e?.code!=="EEXIST")throw e;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
  }
  if(!file)throw Error("PROVIDER_BUSY");
  try{return await callback();}
  finally{await file.close();await unlink(LOCK).catch(()=>{});}
}
export async function updateProvider(id,enable,env=process.env,{root=ROOT}={}){
  if(!IDS.includes(id) || typeof enable!=="boolean")throw Error("INVALID_PROVIDER");
  if(env.CLOUD_FORCE_MAINTENANCE==="true")throw Error("MAINTENANCE_LOCKED");
  if(enable && !providerPrerequisite(id,env))throw Error("PROVIDER_NOT_CONFIGURED");
  return locked(async()=>{
    const state=await loadProviderState(root);
    const disabled=new Set(state.disabled);
    if(enable)disabled.delete(id);else disabled.add(id);
    if(disabled.size===state.disabled.length && [...disabled].every(v=>state.disabled.includes(v)))
      return providerOverview(env,{root});
    // A version above the current epoch-offset seconds prevents stale Android
    // catalogs even across a fresh deployment or a previous QA version bump.
    const floor=Math.floor(Date.now()/1000)-1_577_836_800;
    const version=Math.max(state.version,activeCatalogVersion(env),floor)+1;
    if(version>=1_000_000_000)throw Error("CATALOG_VERSION_EXHAUSTED");
    const updated={...state,version,disabled:[...disabled].sort()};
    const STATE=join(root,"switches.json");
    const tmp=join(root,".switches-"+randomUUID());
    const file=await open(tmp,"wx",0o600);
    try{await file.writeFile(JSON.stringify(updated)+"\n","utf8");await file.sync();}
    finally{await file.close();}
    try{await rename(tmp,STATE);}
    catch(e){await unlink(tmp).catch(()=>{});throw e;}
    return {
      catalogVersion:version,
      providers:IDS.map(k=>({
        id:k,name:LABELS[k],configured:providerPrerequisite(k,env),
        enabled:providerEffective(k,updated,env),
      })),
    };
  },root);
}
