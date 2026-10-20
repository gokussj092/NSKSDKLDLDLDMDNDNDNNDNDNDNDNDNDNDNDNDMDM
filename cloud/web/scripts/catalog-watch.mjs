/** Production opt-in watcher. Dedicated Docker service publishes new catalog version once. */
import {createClient} from "redis";
import {publishCatalogUpdate,pushSettings} from "../lib/c10-catalog-push.mjs";
const redisUrl=process.env.CLOUD_REDIS_URL;
if(process.env.CLOUD_FCM_ENABLED!=="true"||!pushSettings().enabled){
 process.stderr.write("Catalog push is not configured.\n");process.exit(1);
}
if(redisUrl!=="redis://redis:6379")throw Error("INVALID_PRIVATE_REDIS");
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const redis=createClient({url:redisUrl,socket:{connectTimeout:4000,reconnectStrategy:false}});
redis.on("error",()=>{});
for(;;){
 try{
  if(!redis.isOpen)await redis.connect();
  const result=await publishCatalogUpdate(redis);
  if(result.status==="published")process.stdout.write("Catalog update delivered to FCM topic.\n");
 }catch{
  // No credentials, hostnames or payloads in logs.
  process.stderr.write("Catalog publication failed; retrying.\n");
  if(redis.isOpen)try{await redis.quit();}catch{}
 }
 await pause(300000);
}
