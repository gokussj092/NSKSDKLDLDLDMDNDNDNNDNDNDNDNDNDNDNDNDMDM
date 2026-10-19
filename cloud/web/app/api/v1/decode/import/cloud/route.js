import { externalImportRequest } from "../../../../../../lib/c35-gateway.mjs";
import { enabled, notEnabled } from "../../../../../../lib/c3-gateway.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return enabled()?externalImportRequest(request,"ehi"):notEnabled();}
