import {nginxV1Gate} from '../../../../lib/v1-gate.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=()=>nginxV1Gate();
