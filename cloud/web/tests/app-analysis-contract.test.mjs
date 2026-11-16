import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,existsSync} from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
// Contract between server, Android client and admin panel for app analysis
// (SP-DECODE Arnes, fase 1). Field names must match exactly; a rename in one
// place without the others breaks the job view, the download or the panel.
const JOB_FIELDS=['jobId','status','phaseCode','progressPercent','receivedBytes',
 'totalBytes','filename','packageName','appName','creditState','errorCode',
 'needsToken','isNewCatalogCandidate','resultBytes','resultSha256','downloadUrl',
 'expiresAt','createdAt','updatedAt'];
const PREFLIGHT_FIELDS=['creditsAvailable','balance','held','creditPriceCents',
 'currency','creditsPerAnalysis'];
const CANDIDATE_FIELDS=['providerId','jobId','status','packageName','appName',
 'jobStatus','hasIcon','hasCatalog','hasTexts','reviewedBy','reviewedAt','createdAt'];

test('job + preflight field names match across server, client and panel',()=>{
 const server=read('lib/app-analysis.mjs');
 const client=read('../../android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/AppAnalysisClient.kt');
 const panel=read('app/admin/admin-app-analysis.jsx');
 for(const field of JOB_FIELDS){
  assert(server.includes(field),`server missing ${field}`);
  assert(client.includes('"'+field+'"'),`client missing ${field}`);
 }
 for(const field of PREFLIGHT_FIELDS){
  assert(server.includes(field),`server preflight missing ${field}`);
  assert(client.includes('"'+field+'"'),`client preflight missing ${field}`);
 }
 for(const field of ['jobId','status','phaseCode','errorCode','accountId',
   'packageName','appName','filename','progressPercent','receivedBytes',
   'totalBytes','creditState','createdAt']){
  assert(panel.includes(field),`panel missing ${field}`);
 }
 for(const field of CANDIDATE_FIELDS)
  assert(panel.includes(field),`panel candidate missing ${field}`);
 // The client never renders the server events as a list or timeline.
 const screen=read('../../android/app/src/main/java/com/ghostdeveloper/spdecode/AppAnalysisScreen.kt');
 const screenCode=screen.replace(/\/\*[\s\S]*?\*\//g,'');
 assert(!screenCode.includes('events'),'client must not render events as a list');
 assert(!screenCode.includes('LazyColumn'),'client must not render a timeline');
});

test('no icon or catalog reference ever leaks into a job view or download',()=>{
 const server=read('lib/app-analysis.mjs');
 const publicJob=server.slice(server.indexOf('function publicJob'),
   server.indexOf('async function loadJobForUpdate'));
 assert(!publicJob.includes('icon'),'publicJob must not mention icon');
 assert(!publicJob.includes('catalogRef'),'publicJob must not mention catalogRef');
 assert(server.includes('icon_ref'), 'candidate insert keeps icon_ref internal');
 const client=read('../../android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/AppAnalysisClient.kt');
 assert(!client.includes('iconRef'),'client must never receive iconRef');
 const download=read('app/api/v2/app-analysis/[jobId]/download/route.js');
 assert(!download.includes('icon'),'download must not serve icon refs');
});

test('every app-analysis route exists and the panel is wired into the nav',()=>{
 // Client operations travel over the V2 transport (ops 25-30), not over
 // HTTP routes: preflight/start/chunk/finish/status/history.
 const v2routes=read('lib/v2-routes.mjs');
 for(const [op,route] of [[25,'app-analysis/preflight'],[26,'app-analysis/start'],
   [27,'app-analysis/chunk'],[28,'app-analysis/finish'],[29,'app-analysis/status'],
   [30,'app-analysis/history']])
  assert(v2routes.includes(op+':"'+route+'"'),`op ${op} must map to ${route}`);
 assert(existsSync(new URL('../lib/app-analysis-v2.mjs',import.meta.url)));
 assert(read('lib/app-analysis-v2.mjs').includes('appAnalysisRequest'));
 // Only the bot/download routes exist as HTTP routes, under /api/v2.
 for(const route of ['[jobId]/download','[jobId]/events',
   '[jobId]/complete','[jobId]/fail']){
  assert(existsSync(new URL('../app/api/v2/app-analysis/'+route+'/route.js',import.meta.url)),route);
 }
 // The V1 routes are gone: the client must not be able to reach them.
 assert(!existsSync(new URL('../app/api/v1/app-analysis',import.meta.url)),
   '/api/v1/app-analysis must not exist anymore');
 assert(read('lib/app-analysis.mjs').includes("'/api/v2/app-analysis/'+jobId"),
   'signed download must point at the V2 route');
 assert(existsSync(new URL('../app/api/admin/app-analysis/route.js',import.meta.url)));
 assert(existsSync(new URL('../app/admin/app-analysis/page.jsx',import.meta.url)));
 assert(read('app/admin/app-analysis/page.jsx').includes('export const metadata='));
 const nav=read('app/admin/admin-nav.jsx');
 assert(nav.includes('"/admin/app-analysis"'));
 assert(nav.includes("'/admin/app-analysis':'support.read'"));
 assert(read('scripts/commerce-migrate.mjs').includes('012_app_analysis.sql'));
});

test('client shows SP-DECODE Arnes with its icon and the exact token notice',()=>{
 const screen=read('../../android/app/src/main/java/com/ghostdeveloper/spdecode/AppAnalysisScreen.kt');
 assert(screen.includes('R.drawable.arnes'));
 assert(screen.includes('app_analysis_arnes_name'));
 assert(existsSync(new URL(
   '../../../android/app/src/main/res/drawable-nodpi/arnes.webp',import.meta.url)));
 const es=read('../../android/app/src/main/res/values-es/strings.xml');
 assert(es.includes('Para que el script funcione correctamente es necesario que captures el token necesario de Google Play (de la aplicación instalada desde Google Play).'));
 for(const locale of ['values','values-ar','values-de','values-es','values-fa',
   'values-fr','values-hi','values-in','values-it','values-ja','values-pt-rBR',
   'values-ru','values-tr','values-vi']){
  const strings=read('../../android/app/src/main/res/'+locale+'/strings.xml');
  const count=(strings.match(/name="app_analysis_/g)||[]).length;
  assert.equal(count,52,locale+' has '+count+' app_analysis_ keys, expected 52');
 }
});

test('150 MB cap is set in both the QA service and the QA client',()=>{
 assert(read('../../cloud/apk_analysis/qa_service.py').includes('MAX_APK = 150 * 1000 * 1000'));
 assert(read('../../android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudApkQaClient.kt')
  .includes('MAX_BYTES=150L*1000L*1000L'));
 assert(read('lib/app-analysis.mjs').includes('MAX_APK_BYTES=150*1000*1000'));
});
