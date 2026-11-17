import {inputLinkRequest} from '../../../../../../lib/app-analysis-input.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export async function GET(request,{params,...options}){
 const {jobId}=await params;
 return inputLinkRequest(request,jobId,options);
}
