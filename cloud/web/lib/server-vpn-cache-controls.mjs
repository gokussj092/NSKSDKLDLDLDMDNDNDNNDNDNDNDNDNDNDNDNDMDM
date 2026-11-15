/** Eligibility and revision for the fixed-provider server cache. */
import {readFileSync} from "node:fs";
import {join} from "node:path";
import {loadProviderState,providerEffective} from "./c12-provider-controls.mjs";
import {maintenanceEnabled,serviceMaintenanceEnabled} from "./c6-ops-store.mjs";
import {activeCatalogVersion} from "./server-vpn-catalog.mjs";
import {cacheable} from "./server-vpn-result-cache.mjs";
let buildId="source";
try{buildId=readFileSync(join(process.cwd(),".next","BUILD_ID"),"utf8").trim()||buildId;}catch{}
const revision=(state,id)=>JSON.stringify([buildId,activeCatalogVersion(),state.version,state.methodRevisions?.[id]??0,
 process.env.CLOUD_SERVER_VPN_CACHE_REVISION||"1"]);
export async function catalogCacheConfig(redis,id,load){
 if(!cacheable(id))return {id,load,enabled:false};
 const state=await loadProviderState();
 const currentRevision=revision(state,id);
 return {id,revision:currentRevision,load,isCurrent:async()=>{
  const latest=await loadProviderState();
  return providerEffective(id,latest)&&revision(latest,id)===currentRevision&&
   !await maintenanceEnabled(redis)&&!await serviceMaintenanceEnabled(redis,"serverVpn");
 }};
}
