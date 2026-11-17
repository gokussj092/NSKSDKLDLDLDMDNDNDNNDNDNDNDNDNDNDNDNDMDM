import {safe,reply,jsonBody} from '../../../../lib/commerce/config.mjs';
import {requirePanel,can} from '../../../../lib/commerce/staff.mjs';
import {adminSettings,validMutation} from '../../../../lib/c6-admin-auth.mjs';
import {listAdminJobs,listCandidates,reviewCandidate,STATUSES} from '../../../../lib/app-analysis.mjs';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Panel: job list + catalog-candidate review. Reading needs support.read;
// reviewing a candidate needs support.write. Review only flips
// pending -> approved/rejected; promoting to the public catalog stays a
// manual step by Ghost Developer and is deliberately NOT implemented here.
export const GET=request=>safe(async()=>{
 const principal=await requirePanel(request);
 if(!can(principal,'support.read'))return reply({error:{code:'FORBIDDEN'}},403);
 const url=new URL(request.url);
 const status=url.searchParams.get('status')||null;
 if(status!==null&&!STATUSES.has(status))return reply({error:{code:'INVALID_REQUEST'}},400);
 const [jobs,candidates]=await Promise.all([listAdminJobs({status}),listCandidates()]);
 return reply({...jobs,...candidates});
});
export const POST=request=>safe(async()=>{
 const principal=await requirePanel(request);
 if(!can(principal,'support.read'))return reply({error:{code:'FORBIDDEN'}},403);
 if(!validMutation(request,adminSettings()))return reply({error:{code:'CSRF_REJECTED'}},403);
 const body=await jsonBody(request,16*1024);
 if(body?.action!=='reviewCandidate'||!can(principal,'support.write'))
  return reply({error:{code:'FORBIDDEN'}},403);
 return reply(await reviewCandidate(principal,body));
});
