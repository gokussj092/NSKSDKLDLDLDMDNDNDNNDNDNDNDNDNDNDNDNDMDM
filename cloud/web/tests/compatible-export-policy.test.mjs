import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {atLeast,negotiatesExport,exportPolicy,setExportPolicy,exportAllowed,
 projectedCatalogVersion,exportCatalog} from '../lib/compatible-export-policy.mjs';

const request=(v='1.1.21',protocol='1')=>new Request('https://example.test/catalog',{
 headers:{'x-spdecode-app-version':v,'x-spdecode-compatible-export':protocol}});
async function fixture(t){
 const root=await mkdtemp(join(tmpdir(),'spdecode-export-policy-'));
 t.after(()=>rm(root,{recursive:true,force:true}));return {root,env:{}};
}
test('export protocol requires numeric release version and explicit negotiation',()=>{
 for(const v of ['1.1.20','1.1.9','1.1.021','1.1.21-qa','garbage',''])
  assert.equal(negotiatesExport(request(v)),false);
 for(const v of ['1.1.21','1.1.100','1.2.0','2.0.0'])assert(negotiatesExport(request(v)));
 assert(!negotiatesExport(request('1.1.21','')));
 assert(atLeast('1.1.100','1.1.22'));assert(!atLeast('1.1.9','1.1.21'));
});
test('policy defaults off and only new clients receive additive capabilities',async t=>{
 const opts=await fixture(t),p=await exportPolicy(opts);
 assert.equal(p.enabled,false);assert.equal(p.minimumAppVersion,'1.1.21');
 assert.equal(exportCatalog(request('1.1.20'),p),null);
 assert.equal(projectedCatalogVersion(request('1.1.20'),42,p),42);
 assert.equal(projectedCatalogVersion(request(),42,p),43);
 assert.deepEqual(exportCatalog(request(),p).formats,[]);
});
test('panel changes persist atomically and enforce minimum version and revision',async t=>{
 const opts=await fixture(t);
 const p=await setExportPolicy({enabled:true,minimumAppVersion:'1.1.21',expectedRevision:0},opts);
 assert.equal(p.revision,1);assert(exportAllowed(request(),p));
 assert.equal((await stat(join(opts.root,'compatible-export.json'))).mode&0o777,0o600);
 assert.deepEqual(await exportPolicy(opts),p);
 const formats=exportCatalog(request(),p).formats;
 assert.deepEqual(formats.map(x=>x.suffix),['hc','dark','ehi','npvs']);
 assert.equal(formats.find(x=>x.suffix==='dark').banner,'none');
 assert.equal(formats.find(x=>x.suffix==='npvs').banner,'none');
 const p2=await setExportPolicy({enabled:true,minimumAppVersion:'1.1.22',expectedRevision:1},opts);
 assert(!exportAllowed(request(),p2));assert(exportAllowed(request('1.1.22'),p2));
 assert.equal(projectedCatalogVersion(request(),42,p2),45);
 await assert.rejects(setExportPolicy({enabled:true,minimumAppVersion:'1.1.20',expectedRevision:2},opts),{code:'INVALID_REQUEST'});
 await assert.rejects(setExportPolicy({enabled:true,minimumAppVersion:'1.1.22',expectedRevision:0},opts),{code:'EXPORT_POLICY_CONFLICT'});
});
test('concurrent admin edits cannot overwrite each other',async t=>{
 const opts=await fixture(t),input={enabled:true,minimumAppVersion:'1.1.21',expectedRevision:0};
 const results=await Promise.allSettled([setExportPolicy(input,opts),setExportPolicy(input,opts)]);
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.find(x=>x.status==='rejected').reason.code,'EXPORT_POLICY_CONFLICT');
 assert.equal((await exportPolicy(opts)).revision,1);
});
test('HA export is additive and old clients retain the exact four-target catalog',()=>{
 const policy={schemaVersion:1,revision:4,enabled:true,minimumAppVersion:'1.1.21'};
 const old=request(),current=request();current.headers.set('x-spdecode-compatible-export-hat','1');
 assert.deepEqual(exportCatalog(old,policy).formats.map(x=>x.suffix),['hc','dark','ehi','npvs']);
 const formats=exportCatalog(current,policy).formats;
 assert.deepEqual(formats.map(x=>x.suffix),['hc','dark','ehi','npvs','hat']);
 assert.deepEqual(formats.at(-1),{suffix:'hat',targetAppId:'ha-tunnel-plus',name:'HA Tunnel Plus',banner:'none'});
 assert.equal(projectedCatalogVersion(current,59,policy),projectedCatalogVersion(old,59,policy)+1);
 for(const invalid of ['0','true','2']){
  current.headers.set('x-spdecode-compatible-export-hat',invalid);
  assert.equal(exportCatalog(current,policy).formats.length,4);
 }
});
test('VPS emergency lock overrides panel and corrupt state fails closed',async t=>{
 const opts=await fixture(t);
 await setExportPolicy({enabled:true,minimumAppVersion:'1.1.21',expectedRevision:0},opts);
 const locked={...opts,env:{CLOUD_COMPATIBLE_EXPORT_LOCKED:'true'}};
 assert.equal((await exportPolicy(locked)).enabled,false);
 await assert.rejects(setExportPolicy({enabled:true,minimumAppVersion:'1.1.21',expectedRevision:1},locked),{code:'EXPORT_POLICY_LOCKED'});
 await writeFile(join(opts.root,'compatible-export.json'),'{"enabled":true}');
 await assert.rejects(exportPolicy(opts),/EXPORT_POLICY_INVALID/);
 assert.equal(await readFile(join(opts.root,'compatible-export.json'),'utf8'),'{"enabled":true}');
});
