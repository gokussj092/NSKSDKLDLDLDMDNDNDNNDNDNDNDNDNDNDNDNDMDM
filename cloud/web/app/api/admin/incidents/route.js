import {adminDiagnosticsRequest} from "../../../../lib/c9-admin-diagnostics.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function GET(request){return adminDiagnosticsRequest(request);}
