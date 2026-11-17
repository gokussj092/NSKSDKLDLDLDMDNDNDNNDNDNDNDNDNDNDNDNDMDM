import {inputQueueRequest} from '../../../../../lib/app-analysis-input.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const GET=(request,options={})=>inputQueueRequest(request,options);
