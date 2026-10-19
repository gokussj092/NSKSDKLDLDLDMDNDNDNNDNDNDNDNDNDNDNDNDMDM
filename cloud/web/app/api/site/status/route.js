import { settings } from "../../../../lib/c3-config.mjs";
import { store } from "../../../../lib/c3-store.mjs";
import { maintenanceEnabled } from "../../../../lib/c6-ops-store.mjs";
import { jsonReply } from "../../../../lib/responses.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export async function GET(){
  // Public telemetry is intentionally binary: never disclose inner topology,
  // vendor configuration, Redis metrics, user data or worker credentials.
  if(!settings().configured)
    return jsonReply({status:"not_ready",phase:"prelaunch"},200);
  try {
    const redis=await store();
    if(await maintenanceEnabled(redis))
      return jsonReply({status:"maintenance",phase:"prelaunch"},200);
    if(await redis.ping()!=="PONG")throw Error("unavailable");
    // Test private worker readiness without exposing the internal topology.
    if(process.env.WORKER_INTERNAL_URL!=="http://decoder-worker:8787")throw Error("unavailable");
    const response=await fetch("http://decoder-worker:8787/ready",{
      signal:AbortSignal.timeout(3500),redirect:"error",cache:"no-store",
    });
    if(!response.ok)throw Error("unavailable");
    // C6 never claims production readiness before C7/C8.
    return jsonReply({status:"testing",phase:"prelaunch"},200);
  }catch {
    return jsonReply({status:"not_ready",phase:"prelaunch"},200);
  }
}
