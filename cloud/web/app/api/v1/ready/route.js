import { enabled, readinessRequest } from "../../../../lib/c3-gateway.mjs";
import { ready } from "../../../../lib/public-contract.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function GET(){return enabled()?readinessRequest():ready();}
