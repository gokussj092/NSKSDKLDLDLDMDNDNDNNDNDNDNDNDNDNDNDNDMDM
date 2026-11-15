#!/usr/bin/env python3
"""Reproducible synthetic host checks. Never invokes Gradle or an Android build."""
import argparse, hashlib, json, os, platform, re, subprocess, sys, tempfile, time
from pathlib import Path
import xml.etree.ElementTree as ET
ROOT=Path(__file__).resolve().parents[2]
JAVA=ROOT/'android/app/src/main/java/com/ghostdeveloper/spdecode'
CPP=ROOT/'android/app/src/main/cpp'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache',type=Path,required=True)
    p.add_argument('--jni-include',type=Path,required=True,help='OpenJDK include directory, with linux/jni_md.h')
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();report={'schemaVersion':1,'syntheticOnly':True,'androidBuildRun':False,'deviceQaRun':False,'platform':platform.platform(),'checks':[]}
    def run(name,cmd,env=None,cwd=ROOT):
        start=time.monotonic();result=subprocess.run([str(x) for x in cmd],cwd=cwd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180,env=env)
        report['checks'].append({'name':name,'exitCode':result.returncode,'seconds':round(time.monotonic()-start,3),'output':result.stdout[-16000:]})
        print(name+': '+('PASS' if result.returncode==0 else 'FAIL'),flush=True)
        if result.returncode:raise RuntimeError(name+' failed: '+result.stdout[-3000:])
        return result.stdout
    try:
        kt=sorted(JAVA.glob('*.kt'))+sorted((JAVA/'cloud').glob('*.kt'))+sorted((JAVA/'results').glob('*.kt'))+sorted((ROOT/'android/app/src/androidTest/java/com/ghostdeveloper/spdecode').glob('*.kt'))+list((ROOT/'tests/host').glob('*.kt'))
        run('kotlin_psi_syntax_only',[sys.executable,'scripts/qa/kotlin_syntax.py','--cache',a.cache,*kt])
        report['dependencies']=json.loads((a.cache/'dependencies.json').read_text())
        report['jniHeaders']=[{'name':str(x.relative_to(a.jni_include)),'sha256':sha(x)} for x in [a.jni_include/'jni.h',a.jni_include/'linux/jni_md.h']]
        with tempfile.TemporaryDirectory(prefix='spdecode-results-qa-') as temporary:
            temp=Path(temporary);native=temp/'result-test';library=temp/'libspdecode_result_engine.so'
            run('native_asan_ubsan_compile',['g++','-std=c++17','-Wall','-Wextra','-Werror','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',CPP,CPP/'result_engine.cpp','tests/native/result_engine_test.cpp','-o',native])
            env=os.environ.copy();env['ASAN_OPTIONS']='detect_leaks=0'
            run('native_asan_ubsan_no_leaksanitizer',[native],env)
            run('host_jni_compile',['g++','-std=c++17','-Wall','-Wextra','-Werror','-shared','-fPIC','-I',a.jni_include,'-I',a.jni_include/'linux',CPP/'result_engine.cpp',CPP/'result_engine_jni.cpp','-o',library])
            run('host_jni_java_contract',['java','tests/native/result_engine_jni/NativeResultEngine.java',library])
            fixture=temp/'fixture.json';run('publisher_fixture',['node','scripts/qa/catalog_fixture.mjs',fixture])
            cp=':'.join(str(x) for x in sorted(a.cache.glob('*.jar')));out=temp/'kotlin';out.mkdir()
            sources=[JAVA/x for x in ['DecodedResultSnapshot.kt','ResultSnapshotCodec.kt','ResultOutputWriter.kt','ResultJsonDisplay.kt','ResultPresentation.kt','DecoderPresentation.kt','results/NativeResultEngine.kt','cloud/CatalogSnapshotDownload.kt']]+sorted((ROOT/'tests/host').glob('*.kt'))
            run('kotlin_production_algorithms_compile',['java','-cp',cp,'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-classpath',cp,'-d',out,*sources])
            run('kotlin_production_algorithms_execute',['java','-Djava.library.path='+str(temp),'-cp',str(out)+':'+cp,'com.ghostdeveloper.spdecode.Catalog_results_testKt',fixture])
        output=run('node_local_regressions',['node','--test',*sorted((ROOT/'cloud/web/tests').glob('*.test.mjs'))],cwd=ROOT/'cloud/web');counts=re.findall(r'(?:ℹ|#) (tests|pass|fail|skipped) (\d+)',output);report['nodeCounts']=dict(counts)
        resources=sorted((ROOT/'android/app/src/main/res').glob('values*/strings.xml'))
        for path in resources:
            root=ET.parse(path).getroot();names=[x.attrib['name'] for x in root.findall('string')];assert len(names)==len(set(names)),str(path)
            for name in ['catalog_transfer_verifying','result_engine_error','result_previous_page','result_copy_too_large','catalog_transfer_paused','catalog_transfer_resume','catalog_transfer_discard','catalog_transfer_retention']:assert name in names,(path,name)
        report['checks'].append({'name':'xml_unique_keys_all_locales','exitCode':0,'files':len(resources)})
        report['status']='HOST_CHECKS_PASSED_DEVICE_GATES_PENDING'
    finally:
        a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
if __name__=='__main__':main()
