import {diagnosticRequest} from "../../../../lib/c9-diagnostics-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return diagnosticRequest(request);}
