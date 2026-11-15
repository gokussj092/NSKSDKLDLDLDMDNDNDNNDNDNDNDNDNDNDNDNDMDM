import {apkQaRequest} from "../../../../../lib/f7-apk-qa-gateway.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
// This route MUST reject direct public requests. V2's private WeakMap claims
// are never set by client-provided HTTP headers.
export const POST=request=>apkQaRequest(request,21);
