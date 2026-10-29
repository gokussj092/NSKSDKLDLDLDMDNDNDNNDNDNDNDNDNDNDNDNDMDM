import {adminV1Protection} from '../../../../lib/v1-security-admin.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=request=>adminV1Protection(request);
export const POST=request=>adminV1Protection(request);
