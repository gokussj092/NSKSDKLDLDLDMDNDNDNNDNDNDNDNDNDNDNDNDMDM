import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync,existsSync,statSync} from "node:fs";
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
 const icon=read("app/icon.svg"),original=read("../../android/app/src/main/res/mipmap-anydpi/ic_launcher.xml");
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
 const files=["01-home.jpg","02-history.jpg","03-formats.jpg","04-settings.jpg"];
 for(const file of files){
  assert.ok(home.includes(file),"unreferenced "+file);
  const asset=new URL("public/screenshots/"+file,root);
  assert.ok(existsSync(asset),"missing "+file);
  assert.ok(statSync(asset).size>2000,"truncated "+file);
  assert.deepEqual(Array.from(readFileSync(asset).subarray(0,3)),[255,216,255],"invalid JPEG "+file);
 }
});
test("ES and EN complete and legal pages remain available",()=>{
 const home=read("app/public/home.jsx"),legal=read("app/public/legal.jsx");
 assert.match(home,/Make your configurations clearer/);
 assert.match(home,/Tus configuraciones, más claras/);
 assert.match(legal,/Política de privacidad de SP-DECODE/);
 assert.match(legal,/SP-DECODE Privacy Policy/);
 assert.match(legal,/October 25, 2026/);
 for(const page of ["app/privacy/page.jsx","app/terms/page.jsx","app/support/page.jsx"])
  assert.match(read(page),/PublicLegal/);
});

test("public header hides legal links while the footer retains privacy, terms and support",()=>{
 const chrome=read("app/public/site-chrome.jsx");
 const header=chrome.slice(chrome.indexOf('<header className="sp-public-header">'),chrome.indexOf('</header>')+9);
 const footer=chrome.slice(chrome.indexOf('<footer className="sp-public-footer">'),chrome.indexOf('</footer>')+9);
 for(const path of ["/privacy","/terms","/support"]){
  assert.ok(!header.includes('href="'+path+'"'),"header exposes "+path);
  assert.ok(footer.includes('href="'+path+'"'),"footer missing "+path);
 }
 assert.ok(!header.includes('className="sp-nav"'));
 assert.ok(header.includes('className="sp-logo"'));
 assert.ok(header.includes('className="sp-language"'));
});
test("Google Play-style gallery scrolls horizontally without manual navigation buttons",()=>{
 const home=read("app/public/home.jsx"),css=read("app/public/public.css");
 const gallery=home.slice(home.indexOf("function Gallery({t})"),home.indexOf("export default function Home(){"));
 assert.ok(gallery.includes('className="sp-gallery-viewport"'));
 assert.ok(gallery.includes("onPointerMove"));
 assert.ok(gallery.includes("onKeyDown"));
 assert.ok(gallery.includes('role="region"'));
 assert.ok(!gallery.includes("<button"));
 assert.ok(!gallery.includes("translateX("));
 for(const selector of ["overflow-x:auto","scroll-snap-type:x mandatory","scroll-snap-align:start"])assert.ok(css.includes(selector));
 assert.ok(home.includes("Desliza horizontalmente"));
 assert.ok(home.includes("Swipe horizontally"));
});

test("Google Play button is disabled and cannot redirect to GitHub",()=>{
 const home=read("app/public/home.jsx");
 const css=read("app/public/public.css");
 assert.doesNotMatch(home,/github\.com|\/releases|href=.*download/i);
 assert.match(home,/play:"Google Play"/);
 assert.match(home,/download:"Próximamente"/);
 assert.match(home,/download:"Coming soon"/);
 assert.match(home,/<button className="sp-button sp-button-play-pending"[^>]*disabled/);
 assert.match(home,/\{t\.play\}/);
 assert.match(css,/\.sp-button-play-pending:disabled\{cursor:not-allowed\}/);
});
