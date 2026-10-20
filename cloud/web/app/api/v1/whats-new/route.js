import {whatsNewRequest} from "../../../../lib/whats-new.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export function POST(request){return whatsNewRequest(request);}
