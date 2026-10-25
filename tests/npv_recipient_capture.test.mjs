// Observer control flow on host mocks, not a physical Android/Frida test.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
const source=readFileSync(new URL('../scripts/apk_analysis/npv_recipient_capture.js',import.meta.url),'utf8');
function harness({failure=false,software=false,otherFile=false,version=577}={}){
    const raw=Array(400).fill(0);raw.splice(0,5,...Buffer.from('NPVS'),6);
    raw[8]=240;raw[9]=1;raw[61]=1;
    const fp=Array.from({length:32},(_,i)=>i+1);raw.splice(62,32,...fp);
    raw.splice(94,33,2,...Array(32).fill(7));
    const shared=Array(32).fill(9),privateBytes=Array(138).fill(8),logs=[],calls=[];
    const app={getPackageName:()=> 'com.napsternetlabs.napsternetv',getPackageManager:()=>({
        getPackageInfo:()=>({versionCode:{value:version},versionName:{value:'124.0.37'}})})};
    const soft={call:()=>privateBytes};
    const open={call(receiver,...args){calls.push({receiver,args});shared.fill(0);
        if(failure)throw Error('original denied import');return result;}};
    const result={success:true};
    const classes={
        'android.app.ActivityThread':{currentApplication:()=>app},
        'android.util.Base64':{encodeToString:value=>Buffer.from(value).toString('base64url')},
        'java.security.MessageDigest':{getInstance:()=>({digest:value=>Array.from(createHash('sha256').update(Buffer.from(value)).digest())})},
        'ah.i':{c:{overload:()=>soft}},
        'libnpvtunnel.Libnpvtunnel':{openCompactEnvelopeForImport:{overload:(...signature)=>{
            assert.deepEqual(signature,['[B','[B','[B','[B','[B','int','long']);return open;}}}
    };
    const hash=createHash('sha256').update(Buffer.from(raw)).digest('hex');
    const initialize=()=>vm.runInNewContext(source.replace('__TARGET_SHA256__',otherFile?'0'.repeat(64):hash),{
        Java:{perform:fn=>fn(),array:(_,value)=>value,use:name=>classes[name]},console:{log:value=>logs.push(value)}});
    const receiver={},args=[raw,shared,fp,[],[],0,123];
    return {initialize,invoke:()=>open.implementation.call(receiver,...args),soft,logs,calls,args,receiver,result,
        captures:()=>logs.filter(line=>line.startsWith('SPDECODE_NPV_CAPTURE ')).map(line=>JSON.parse(line.slice(21)))};
}
test('hardware capture preserves arguments and snapshots agreement before native cleanup',()=>{
    const h=harness();h.initialize();assert.equal(h.invoke(),h.result);
    assert.equal(h.calls[0].receiver,h.receiver);assert.deepEqual(h.calls[0].args,h.args);
    const [capture]=h.captures();assert.equal(capture.kind,'agreement');
    assert.equal(capture.sharedSecret,Buffer.alloc(32,9).toString('base64url'));
    assert(!('privateKey' in capture));h.invoke();assert.equal(h.captures().length,1);
});
test('software PKCS8 is copied before caller cleanup and emitted only after successful target import',()=>{
    const h=harness();h.initialize();const original=h.soft.implementation();original.fill(0);
    assert.equal(h.captures().length,0);h.invoke();
    assert.equal(h.captures()[0].kind,'private-pkcs8');
    assert.equal(h.captures()[0].privateKey,Buffer.alloc(138,8).toString('base64url'));
});
test('denied imports, other files and unanalysed builds cannot emit material',()=>{
    const denied=harness({failure:true});denied.initialize();assert.throws(denied.invoke,/original denied/);
    assert.equal(denied.captures().length,0);
    const other=harness({otherFile:true});other.initialize();other.invoke();assert.equal(other.captures().length,0);
    assert.throws(harness({version:578}).initialize,/Only NPV/);
});
