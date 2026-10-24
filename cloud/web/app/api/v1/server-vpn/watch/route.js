import {catalogWatchRequest} from "../../../../../lib/c10-catalog-watch.mjs";
export const runtime="nodejs";
export const dynamic="force-dynamic";
export const maxDuration=25;
export function POST(request){return catalogWatchRequest(request);}
