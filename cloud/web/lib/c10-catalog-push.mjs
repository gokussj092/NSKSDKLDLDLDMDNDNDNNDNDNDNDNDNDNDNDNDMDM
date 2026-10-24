/** VPS-only catalog notices. No FCM, device accounts, tokens or external services. */
import {providerOverview} from "./c12-provider-controls.mjs";
export const ANNOUNCED_VERSION_KEY="spc10:catalog:last-announced";
export function pushSettings(){return {enabled:true,transport:"own-vps-https-watch"};}
/** Admin-only status: version activation is authoritative in the VPS environment. */
export async function publishCatalogUpdate(redis,{env=process.env}={}){
 const version=(await providerOverview(env,{syncCatalog:true})).catalogVersion;
 const before=Number(await redis.get(ANNOUNCED_VERSION_KEY)||0);
 if(before>=version)return {status:"unchanged",version};
 // Store a monotonic last-confirmed version; never claim a message reached a phone.
 await redis.set(ANNOUNCED_VERSION_KEY,String(version));
 return {status:"registered",version};
}
