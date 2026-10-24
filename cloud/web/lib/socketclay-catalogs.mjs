/** Compatibility wrapper for the original paired-catalog provider. */
import {packPairedVpnCatalogs,PAIRED_CATALOG_LIMIT} from "./paired-vpn-catalogs.mjs";
export const SOCKETCLAY_BUNDLE_LIMIT=PAIRED_CATALOG_LIMIT;
export function packSocketClayCatalogs(sources){return packPairedVpnCatalogs("http-socketclay",sources);}
