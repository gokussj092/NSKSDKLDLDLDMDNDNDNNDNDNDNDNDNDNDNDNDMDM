import {mobileAdminRequest} from '../../../../lib/commerce/mobile-admin.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=request=>mobileAdminRequest(request);
export const POST=request=>mobileAdminRequest(request);
