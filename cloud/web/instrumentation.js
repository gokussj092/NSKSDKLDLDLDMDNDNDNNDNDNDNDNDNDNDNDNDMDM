/** Next.js starts exactly one logical refresh loop per Node process.
 * Redis leases coordinate separate processes and request bundles. */
export async function register(){
 if(process.env.NEXT_RUNTIME==="nodejs"&&process.env.CLOUD_SERVER_VPN_CACHE_ENABLED==="true"){
  const {startCatalogRefresh}=await import("./lib/server-vpn-cache-refresh.mjs");
  startCatalogRefresh();
 }
}
