/** Node-only refresh scheduler. No public endpoint or synthetic user account. */
import {randomUUID} from "node:crypto";
import {settings} from "./c3-config.mjs";
import {store,reserveSlot,releaseSlot} from "./c3-store.mjs";
import {failure} from "./c3-gateway.mjs";
import {maintenanceEnabled,serviceMaintenanceEnabled,recordWorkerResult} from "./c6-ops-store.mjs";
import {providerIds} from "./server-vpn-provider.mjs";
import {providerAllowed} from "./c12-provider-controls.mjs";
import {loadServerVpnResult} from "./server-vpn-gateway.mjs";
import {loadNurCatalogResult} from "./c35-gateway.mjs";
import {catalogCacheConfig} from "./server-vpn-cache-controls.mjs";
import {cacheEnabled,cacheable,renewDemandedCatalog} from "./server-vpn-result-cache.mjs";
const schedulerId="internal-catalog-refresh";
async function runProvider(redis,id){
 const lease=randomUUID();
 if(!await reserveSlot(redis,schedulerId,lease))return failure("RATE_LIMITED",429);
 let bytes=0;const start=performance.now();
 const kind=id==="nur-tunnel"?"catalog":"server-vpn";
 try{
  const result=id==="nur-tunnel"?await loadNurCatalogResult({},n=>{bytes=n;}):
   await loadServerVpnResult(id,{},n=>{bytes=n;});
  // Record only the real worker job; cache hits never increment decode metrics.
  let code="",outcome=result.ok?"success":"failed";
  if(!result.ok||id==="mkk-hyper"){try{
    const data=await result.clone().json();
    if(!result.ok)code=data.error?.code||"";
    else if(data.isPartial===true){code="PARTIAL_SOURCE_FAILURE";outcome="warning";}
  }catch{}}
  await recordWorkerResult(redis,outcome,{kind,
   format:id,bytes,errorCode:code,latencyMs:performance.now()-start}).catch(()=>{});
  return result;
 }catch(error){
  await recordWorkerResult(redis,"failed",{kind,format:id,bytes,errorCode:error?.code||"SERVICE_UNAVAILABLE",
    latencyMs:performance.now()-start}).catch(()=>{});
  throw error;
 }finally{await releaseSlot(redis,schedulerId,lease).catch(()=>{});}
}
export async function refreshCatalogOnce(){
 if(!cacheEnabled()||!settings().configured)return false;
 const redis=await store();
 if(await maintenanceEnabled(redis)||await serviceMaintenanceEnabled(redis,"serverVpn"))return false;
 const configs=[];
 for(const id of [...providerIds(),"nur-tunnel"]){
  if(!cacheable(id)||!await providerAllowed(id))continue;
  configs.push(await catalogCacheConfig(redis,id,()=>runProvider(redis,id)));
 }
 return renewDemandedCatalog(redis,configs);
}
export function startCatalogRefresh(){
 if(!cacheEnabled())return;
 const key=Symbol.for("spdecode.catalog.refresh.v1");
 if(globalThis[key])return;
 let running=false;
 const timer=setInterval(async()=>{
  if(running)return;running=true;
  try{await refreshCatalogOnce();}catch{/* Never log catalog payloads, keys or URLs. */}
  finally{running=false;}
 },10_000);
 timer.unref?.();globalThis[key]=timer;
}
