import {catalogEditionRequest} from "../../../../lib/c6-admin-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const POST=request=>catalogEditionRequest(request);
