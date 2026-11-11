import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=name=>readFileSync(new URL('../'+name,import.meta.url),'utf8');

test('store uses the supplied emerald reference but real provider checkout',()=>{
 const store=read('app/public/storefront.jsx');
 const experience=read('app/public/store-experience.jsx');
 const css=read('app/public/public.css');
 assert.match(store,/import StoreExperience/);
 assert.match(store,/shopFetch\('\/api\/store\/quote'/);
 assert.match(store,/shopFetch\('\/api\/store\/checkout'/);
 for(const id of ['offline-3','api-ip','analysis-credits','online'])
  assert.ok(experience.includes(id),id);
 for(const label of ['Qué incluye','Qué no incluye','Resumen','Desliza'])
  assert.ok((experience+css).includes(label),label);
 assert.ok(css.includes('#2fe07c'));
 assert.match(experience,/sp-shop-summary/);
 assert.match(experience,/PlanCarousel/);
 assert.doesNotMatch(store,/Math\.random\(\)|cc-number|cc-csc|Pago confirmado!/);
});

test('verified APK download endpoint is read only and uses an atomic public slot',()=>{
 const route=read('app/api/downloads/[channel]/route.js');
 const compose=read('../compose.yaml');
 assert.match(route,/new Set\(\['online','offline'\]\)/);
 assert.match(route,/readFile\(prefix\+'\.json'/);
 assert.match(route,/realpath\(join\(ROOT,key,'current'\)\)/);
 assert.match(route,/attachment; filename/);
 assert.match(route,/application\/vnd\.android\.package-archive/);
 assert.match(compose,/\/app\/public-apks:ro/);
 assert.doesNotMatch(route,/exec\(|spawn\(|child_process|eval\(/);
});
test('home offers both APK variants without removing the disabled Play placeholder',()=>{
 const home=read('app/public/home.jsx');
 const downloads=read('app/public/apk-downloads.jsx');
 assert.match(home,/ApkDownloads/);
 assert.match(home,/sp-button-play-pending/);
 assert.match(downloads,/api\/downloads\//);
 assert.match(downloads,/online','offline/);
 assert.match(downloads,/SHA-256/);
});
