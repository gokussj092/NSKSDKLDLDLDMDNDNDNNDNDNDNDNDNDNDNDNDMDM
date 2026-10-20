import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const read=path=>readFileSync(new URL("../"+path,import.meta.url),"utf8");
test("admin shell is isolated from marketing site and places legal links in footer",()=>{
 const chrome=read("app/public/site-chrome.jsx");
 assert.match(chrome,/pathname\?\.startsWith\("\/admin"\)/);
 const admin=chrome.slice(chrome.indexOf("function AdminChrome"),chrome.indexOf("export default function SiteChrome"));
 const bar=admin.slice(admin.indexOf("<header"),admin.indexOf("</header>"));
 const foot=admin.slice(admin.indexOf("<footer"),admin.indexOf("</footer>"));
 assert.match(bar,/src="\/icon.svg"/);
 for(const path of ["/privacy","/terms","/support"]){
  assert.ok(!bar.includes('href="'+path+'"'),"legal path in admin header: "+path);
  assert.ok(foot.includes('href="'+path+'"'),"missing admin footer route: "+path);
 }
 assert.match(read("app/admin/layout.jsx"),/admin-theme.css/);
 const css=read("app/admin/admin-theme.css");
 assert.match(css,/sp-admin-frame/);
 assert.match(css,/background:#000/);
 assert.match(css,/backdrop-filter:blur/);
 assert.match(read("app/admin/login/page.jsx"),/src="\/icon.svg"/);
});
test("admin presentation contains real server-driven KPIs, separate maintenance toggles and no fake statistics",()=>{
 const dash=read("app/admin/admin-dashboard.jsx");
 const graph=read("app/admin/admin-report.jsx");
 assert.match(dash,/\/api\/admin\/session/);
 assert.match(dash,/\/api\/admin\/maintenance/);
 for(const label of ["httpInjector","serverVpn","files"])assert.ok(dash.includes('"'+label+'"'));
 assert.match(dash,/role="switch"/);
 assert.match(graph,/\/api\/admin\/reports/);
 assert.match(graph,/serviceBreakdown/);
 assert.match(graph,/hourlyLast48/);
 assert.match(graph,/function DailyLine/);
 assert.match(graph,/function HourlyBars/);
 assert.match(graph,/function Incidents/);
 assert.match(graph,/Sin operaciones registradas|Sin operaciones|No hay errores registrados/);
 assert.doesNotMatch(graph,/Math\.random/);
});
test("separate API maintenance state and file vs VPN telemetry preserve existing global override",()=>{
 const store=read("lib/c6-ops-store.mjs");
 const api=read("lib/c6-admin-api.mjs");
 const file=read("lib/c3-gateway.mjs");
 const ehi=read("lib/c35-gateway.mjs");
 const vpn=read("lib/server-vpn-gateway.mjs");
 assert.match(store,/export async function serviceMaintenanceEnabled/);
 assert.match(store,/export async function setServiceMaintenance/);
 assert.match(store,/if\(await maintenanceEnabled\(redis,env\)\)return true/);
 assert.match(store,/serviceErrors:errorServices/);
 assert.match(store,/hourlyLast48:hourly/);
 assert.match(api,/SERVICE_IDS\.includes\(body\.service\)/);
 assert.match(api,/authenticateAdmin/);
 assert.match(file,/serviceMaintenanceEnabled\(redis,"files"\)/);
 assert.match(ehi,/kind==="ehi"\?"httpInjector":"serverVpn"/);
 assert.match(vpn,/serviceMaintenanceEnabled\(redis,"serverVpn"\)/);
});
test("Android maintenance response remains localized instead of exposing raw API failures",()=>{
 const client=read("../../android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudUserErrors.kt");
 assert.match(client,/SERVICE_MAINTENANCE/);
 for(const locale of ["values","values-es","values-ar","values-de","values-fa","values-fr","values-in","values-pt-rBR","values-ru"]){
  const source=read("../../android/app/src/main/res/"+locale+"/cloud_error_strings.xml");
  assert.match(source,/name="cloud_failure_maintenance"/);
 }
});

test("admin icon and legal links are allowlisted on the panel origin",()=>{
 const conf=read("../infra/vps/nginx-config.py");
 for(const path of ["/icon.svg","/terms","/support"])
  assert.ok(conf.includes("location = "+path+" {{"),"missing allowed admin route "+path);
 const admin=read("app/public/site-chrome.jsx");
 const login=read("app/admin/login/page.jsx");
 assert.match(admin,/src="\/icon.svg"/);
 assert.match(login,/src="\/icon.svg"/);
});
