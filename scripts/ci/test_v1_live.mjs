/** Real Next.js + ephemeral Redis + generated Nginx. No production connections. */
import assert from 'node:assert/strict';import {spawn,execFileSync} from 'node:child_process';
import {mkdtemp,readFile,writeFile,rm,mkdir} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';import {randomUUID} from 'node:crypto';
import {createRequire} from 'node:module';
const require=createRequire(resolve('cloud/web/package.json'));
const {createClient}=require('redis');
const {changeV1Policy,v1PolicyStatus}=await import('../../cloud/web/lib/v1-protection-policy.mjs');
const {sign}=await import('../../cloud/web/lib/c3-session.mjs');
const root=await mkdtemp(join(tmpdir(),'spdecode-http-')),policy=join(root,'policy');await mkdir(policy);
const children=[];let redis;
const child=(command,args,options={})=>{const p=spawn(command,args,{stdio:'ignore',...options});children.push(p);return p;};
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function wait(url) {for(let i=0;i<90;i++){try{if((await fetch(url)).status===200)return;}catch{}await pause(500);}throw Error('Test service did not start');}
const key='synthetic-private-http-test-key-'.repeat(3);
try {
 child('redis-server',['--port','16389','--save','','--appendonly','no','--dir',root]);
 redis=createClient({url:'redis://127.0.0.1:16389'});redis.on('error',()=>{});await redis.connect();
 child(process.execPath,['node_modules/next/dist/bin/next','start','-p','3107'],{cwd:resolve('cloud/web'),env:{...process.env,NODE_ENV:'production',CLOUD_V1_POLICY_ROOT:policy,
  CLOUD_API_ENABLED:'true',CLOUD_WORKER_TOKEN:'w'.repeat(48),CLOUD_SESSION_SIGNING_KEY:key,CLOUD_REDIS_URL:'redis://127.0.0.1:16389',CLOUD_TRUST_PROXY:'true',CLOUD_GOOGLE_PLAY_PACKAGE:'com.ghostdeveloper.spdecode',CLOUD_BETA_ADMISSION_ENABLED:'true'}});
 await wait('http://127.0.0.1:3107/api/health/live');
 const cert=join(root,'tls.crt'),tlsKey=join(root,'tls.key');
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=spdecode.test',
  '-addext','subjectAltName=DNS:spdecode.test,DNS:api.spdecode.test,DNS:panel.spdecode.test','-keyout',tlsKey,'-out',cert],{stdio:'ignore'});
 let config=execFileSync('python3',['cloud/infra/vps/nginx-config.py','spdecode.test'],{encoding:'utf8'});
 config=config.replaceAll('listen 80;','listen 8084;').replaceAll('listen 443 ssl;','listen 8447 ssl;')
  .replaceAll('/etc/letsencrypt/live/spdecode.test/fullchain.pem',cert).replaceAll('/etc/letsencrypt/live/spdecode.test/privkey.pem',tlsKey)
  .replaceAll('127.0.0.1:3000','127.0.0.1:3107');
 const path=join(root,'nginx.conf');await writeFile(path,`pid ${root}/nginx.pid;\nerror_log ${root}/nginx-error.log warn;\nevents {}\nhttp {\naccess_log off;\nclient_body_temp_path ${root}/body;\nproxy_temp_path ${root}/proxy;\n${config}\n}\n`);
 execFileSync('nginx',['-t','-p',root,'-c',path],{stdio:'ignore'});child('nginx',['-p',root,'-c',path,'-g','daemon off;']);await pause(500);
 const curl=(route,method='GET',host='api.spdecode.test',tls=true,extra=[])=>{
  const port=tls?8447:8084;
  const out=execFileSync('curl',['--noproxy','*','--silent','--show-error','--path-as-is','--max-time','5','--cacert',cert,
    '--resolve',`${host}:${port}:127.0.0.1`,...(method==='HEAD'?['--head']:['-X',method]),'-o','/dev/null','-w','%{http_code}',...extra,`${tls?'https':'http'}://${host}:${port}${route}`],{encoding:'utf8'});
  return Number(out);
 };
 const now=Math.floor(Date.now()/1000),id=randomUUID();
 const token=sign({iss:'spdecode-cloud',aud:'spdecode-android-v1',scope:'decode',iat:now,exp:now+300,jti:id},key);
 await redis.set('spc3:session:'+id,'1',{EX:300});
 const headers=['-H','Content-Type: application/json','-H','X-SPDecode-App-Version: 1.1.21','-H','Authorization: Bearer '+token,'--data','{}'];
 for(const [available,advanced] of [[true,false],[true,true],[false,false],[false,true]]) {
  let p=await v1PolicyStatus({root:policy});await changeV1Policy('apiEnabled',available,p.revision,{root:policy});
  p=await v1PolicyStatus({root:policy});await changeV1Policy('advancedProtection',advanced,p.revision,{root:policy});
  if(available){
   assert.equal(curl('/api/v1/health'),200);
   assert.equal(curl('/api/v1/decode/text','POST',undefined,true,headers),advanced?401:400,'Android 1.1.21 V1 bearer compatibility');
  }else {
   for(const method of ['GET','HEAD','POST','PUT','DELETE','PATCH','OPTIONS'])
    for(const route of ['/api/v1','/api/v1/','/api/v1/health','/api/v1/ready','/api/v1/session','/api/v1/server-vpn/catalog','/api/v1/decode/file','/api/v1/decode/import/catalog/remote','/api/v1/unknown/','//api/v1//health','/api%2fv1/health'])
     assert.equal(curl(route,method),410,method+' '+route);
   for(const host of ['spdecode.test','panel.spdecode.test'])assert.equal(curl('/api/v1/health','GET',host),410);
   assert.equal(curl('/api/v1/health','GET',undefined,false),410,'HTTP cannot redirect around disabled V1');
  }
  assert.equal(curl('/api/health/live'),200);
  assert.notEqual(curl('/api/v2/security-policy'),410);
  console.log(`LIVE_MATRIX available=${available} advanced=${advanced} OK`);
 }
 await writeFile(join(policy,'v1-protection.json'),'{corrupt');
 assert.equal(curl('/api/v1/health'),503);assert.equal(curl('/api/health/live'),200);assert.notEqual(curl('/api/v2/security-policy'),410);
 console.log('LIVE_STORAGE_FAIL_CLOSED_OK; independent health and V2 remain available');
}finally {
 await redis?.quit().catch(()=>{});for(const p of children.reverse())p.kill('SIGTERM');await pause(250);
 await rm(root,{recursive:true,force:true});
}
