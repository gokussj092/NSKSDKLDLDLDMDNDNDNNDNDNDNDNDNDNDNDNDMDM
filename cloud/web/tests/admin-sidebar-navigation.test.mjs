import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const read=path=>readFileSync(new URL("../"+path,import.meta.url),"utf8");
test("AMOLED admin has left hamburger navigation and a distinct route for every section",()=>{
 const nav=read("app/admin/admin-nav.jsx"),layout=read("app/admin/layout.jsx"),css=read("app/admin/admin-theme.css");
 const routes=["","analytics","reports","requests","diagnostics","system","maintenance","cleanup","api-v1","api-v2",
   "play","providers","exports","catalog","notifications","store","observability","alerts","performance","resources"];
 const matches=[...nav.matchAll(/"\/admin(?:\/([a-z0-9-]+))?"/g)].map(m=>m[1]||"").filter(x=>x!=="login");
 assert.deepEqual(matches,routes);
 assert.match(nav,/aria-expanded={expanded}/);
 assert.match(nav,/aria-controls="sp-admin-sidebar"/);
 assert.match(nav,/aria-current={pathname===url/);
 assert.match(nav,/aria-hidden={!expanded}/);
 assert.match(nav,/inert={!expanded}/);
 assert.match(nav,/onClick=\{\(\)=>setExpanded/);
 assert.match(layout,/<AdminNav>\{children\}<\/AdminNav>/);
 assert.match(css,/sp-admin-hamburger/);
 assert.match(css,/sp-admin-sidebar-scroll/);
 assert.match(css,/@media\(max-width:979px\)/);
 for(const slug of routes.filter(Boolean)){
  const page=read("app/admin/"+slug+"/page.jsx");
  assert.match(page,/export const metadata=/,slug);
  assert.match(page,/id="main"/,slug);
  assert.doesNotMatch(page,/AdminCatalogPush[\s\S]*AdminNotifications/,slug);
 }
});

test("API V1 and V2 controls, providers, exports and maintenance are isolated by view",()=>{
 const component=read("app/admin/admin-dashboard.jsx");
 for(const mode of ["overview","infrastructure","api-v1","api-v2","play","providers","exports","maintenance"])
  assert(component.includes('mode==="'+mode+'"')||mode==="overview");
 assert(component.includes('"/api/admin/v1-retirement"'));
 assert(component.includes('"API_V1_PROGRAMAR_48H"'));
 assert(component.includes('"API_V1_CANCELAR_PROGRAMACION"'));
 assert(component.includes('data.v1Policy?.retireAt'));
 assert(component.includes('expectedRevision:data.v1Policy.revision'));
 assert.match(read("app/admin/system/page.jsx"),/mode="infrastructure"/);
 assert.doesNotMatch(read("app/admin/system/page.jsx"),/AdminNotifications|AdminCatalogPush|AdminObservability/);
 for(const slug of ["api-v1","api-v2","play","providers","exports","maintenance"])
  assert(read("app/admin/"+slug+"/page.jsx").includes('mode="'+slug+'"'));
});

test("notifications have their own route, secure composer, live preview and server history",()=>{
 const view=read("app/admin/admin-notifications.jsx");
 const route=read("app/admin/notifications/page.jsx");
 assert.match(route,/AdminNotifications/);
 for(const text of ["/api/admin/notifications","/api/admin/notifications/verify-fcm",
  "crypto.randomUUID()",'type="submit"',"Vista previa en Android",
  "Notificaciones publicadas","Caducidad","7 días","X-SPDecode-Admin-Action"])
  assert(view.includes(text),text);
 assert(view.includes('maxLength={80}')&&view.includes('maxLength={500}'));
 assert(view.includes('credentials:"same-origin"'));
 assert(view.includes('setList(data.notices'));
 assert(view.includes('window.confirm('));
 assert.doesNotMatch(view,/dangerouslySetInnerHTML|innerHTML/);
});

test("retirement policy persists, uses a strict administrative route and never couples to V2",()=>{
 const policy=read("lib/v1-protection-policy.mjs");
 const gate=read("lib/v1-gate.mjs"),api=read("lib/c6-admin-api.mjs");
 const route=read("app/api/admin/v1-retirement/route.js");
 assert(policy.includes('RETIREMENT_DELAY=2*DAY'));
 assert(policy.includes('now>=p.retireAt'));
 assert(policy.includes("withFileLock(root,'v1-policy'"));
 assert(policy.includes("atomicJson(root,FILE,next)"));
 assert(gate.includes("v1PolicyStatus"));
 assert(api.includes("export async function v1RetirementRequest("));
 assert(api.includes("authenticateAdmin(redis,request,cfg)"));
 assert(api.includes("validMutation(request,cfg)"));
 assert(api.includes("body.expectedRevision"));
 assert(route.includes("v1RetirementRequest"));
 assert(!policy.includes("v2Policy"));
});

test("V2 hardware panel supports patch age, boot controls and private aggregate diagnostics",()=>{
 const page=read("app/admin/admin-dashboard.jsx");
 const api=read("lib/c6-admin-api.mjs");
 const verifier=read("lib/device-security.mjs");
 for(const patch of [12,18,24,36,48])
  assert(page.includes('<option value={'+patch+'}>'),String(patch));
 assert(page.includes('role="switch" aria-label="Comprobar parches V2"'));
 assert(page.includes('role="switch" aria-label="Comprobar arranque V2"'));
 assert(page.includes('"/api/admin/v2-device-admission"'));
 assert(page.includes('"V2_DISPOSITIVOS_CONFIGURAR"'));
 assert(page.includes("Restaurar perfil estricto"));
 assert(page.includes("<AdminV2Diagnostics hardware={data.attestationDiagnostics} play={data.admissionDiagnostics}/>"));
 assert(read("app/admin/admin-v2-diagnostics.jsx").includes("hardware.rejections"));
 assert(api.includes("authenticateAdmin(redis,request,cfg)"));
 assert(api.includes("validMutation(request,cfg)"));
 assert(api.includes("changeV2DevicePolicy"));
 assert(api.includes('"http://key-attestation:8788/stats"'));
 assert(verifier.includes("policyLoader = v2DevicePolicyStatus"));
 assert(verifier.includes("devicePolicy:Date.parse")===false);
 assert(verifier.includes("enforceBoot:policy.enforceBoot"));
 assert(read("app/api/admin/v2-device-admission/route.js").includes("v2DeviceAdmissionRequest"));
});


test("feedback inbox is a standalone, secured and accessible admin page",()=>{
 const page=read("app/admin/requests/page.jsx");
 const ui=read("app/admin/admin-feedback.jsx");
 const api=read("app/api/admin/feedback/route.js");
 const logic=read("lib/feedback-admin.mjs");
 const styles=read("app/admin/admin-theme.css");
 assert.match(page,/AdminFeedback/);
 assert.match(page,/id="main"/);
 assert.match(api,/export const GET=feedbackAdminRequest/);
 assert.match(api,/export const POST=feedbackAdminRequest/);
 assert.match(logic,/authenticateAdmin/);
 assert.match(logic,/validMutation/);
 assert.match(logic,/KEEPTTL/);
 assert.match(logic,/REVISION_CONFLICT/);
 assert.match(logic,/private, no-store/);
 assert.match(ui,/credentials:"same-origin"/);
 assert.match(ui,/X-SPDecode-Admin-Action/);
 assert.match(ui,/aria-expanded/);
 assert.match(ui,/rel="noopener noreferrer"/);
 assert.match(ui,/referrerPolicy="no-referrer"/);
 assert.match(ui,/Nota interna/);
 assert.match(ui,/expectedRevision:selected.revision/);
 assert.match(styles,/sp-feedback-filters/);
 assert.doesNotMatch(ui,/dangerouslySetInnerHTML|innerHTML/);
});
