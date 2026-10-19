import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync,existsSync} from "node:fs";
import {join} from "node:path";
const root=new URL("../",import.meta.url);
const read=p=>readFileSync(new URL(p,root),"utf8");
test("public landing never exposes internal implementation or admin entry",()=>{
 const page=read("app/public/home.jsx");
 const chrome=read("app/public/site-chrome.jsx");
 assert.match(page,/SP-DECODE/);
 assert.doesNotMatch(page,/endpoint|Play Integrity|private worker|admin\/login|\bAPI\b/i);
 assert.match(chrome,/publicRoutes=new Set\(\["\/","\/privacy","\/terms","\/support"\]\)/);
 assert.match(chrome,/function LegacyChrome/);
 assert.match(chrome,/https:\/\/panel.spdecode.xyz\/admin\/login/);
 const isolated=chrome.slice(chrome.indexOf("export function PublicChrome"),chrome.indexOf("function LegacyChrome"));
 assert.doesNotMatch(isolated,/panel.spdecode.xyz|\/admin|\/api/);
});
test("official icon geometry remains identical to original Android launcher",()=>{
 const icon=read("app/icon.svg"),original=read("../android/app/src/main/res/mipmap-anydpi/ic_launcher.xml");
 for(const shape of ["M12,2 L21,5 L21,11.5","M12,4.4 L18.8,6.8","M9.4,11.8 L11.2,13.6"])
 {assert.ok(icon.includes(shape),shape);assert.ok(original.includes(shape),shape);}
});
test("social image and favicon metadata are configured",()=>{
 const root=read("app/layout.jsx");
 const og=read("app/opengraph-image.jsx");
 assert.match(root,/\/icon.svg/);
 assert.match(root,/summary_large_image/);
 assert.match(root,/\/opengraph-image/);
 assert.match(og,/ImageResponse/);
 assert.match(og,/1200,height:630/);
});
test("four real screenshots are referenced and local assets exist",()=>{
 const home=read("app/public/home.jsx");
 const files=["01-home.webp","02-history.webp","03-formats.webp","04-settings.webp"];
 for(const file of files){assert.ok(home.includes(file));assert.ok(existsSync(new URL("public/screenshots/"+file,root)),"missing "+file);}
});
test("ES and EN complete and legal pages remain available",()=>{
 const home=read("app/public/home.jsx"),legal=read("app/public/legal.jsx");
 assert.match(home,/Make your configurations clearer/);
 assert.match(home,/Tus configuraciones, más claras/);
 assert.match(legal,/Política|Privacidad|Privacidad y tratamiento/);
 assert.match(legal,/Privacy and data processing/);
 assert.match(legal,/October 18, 2026/);
 for(const page of ["app/privacy/page.jsx","app/terms/page.jsx","app/support/page.jsx"])
  assert.match(read(page),/PublicLegal/);
});
