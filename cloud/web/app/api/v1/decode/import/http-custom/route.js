import {externalImportRequest} from "../../../../../../lib/c35-gateway.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return externalImportRequest(request,"hc");}
