import {catalogChunkRequest} from "../../../../../lib/catalog-chunk-api.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const POST=request=>catalogChunkRequest("manifest",request);
