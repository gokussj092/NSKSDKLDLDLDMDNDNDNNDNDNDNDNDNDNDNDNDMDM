import {compatibleExportAdmin} from '../../../../lib/compatible-export-admin.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export function GET(request){return compatibleExportAdmin(request);}
export function POST(request){return compatibleExportAdmin(request);}
