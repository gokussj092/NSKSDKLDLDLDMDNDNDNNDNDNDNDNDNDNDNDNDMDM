import { enabled, capabilitiesRequest } from "../../../../lib/c3-gateway.mjs";
import { capabilities } from "../../../../lib/public-contract.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function GET(){return enabled()?capabilitiesRequest():capabilities();}
