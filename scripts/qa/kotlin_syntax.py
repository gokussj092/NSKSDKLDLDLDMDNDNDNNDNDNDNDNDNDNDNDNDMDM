#!/usr/bin/env python3
"""Pinned project-version Kotlin PSI parsing; no Gradle, Android SDK or APK build."""
import argparse,hashlib,json,subprocess,urllib.request
from pathlib import Path
BASE='https://repo.maven.apache.org/maven2/'
DEPENDENCIES=[('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.1.20'),('org.jetbrains.kotlin','kotlin-stdlib','2.1.20'),('org.jetbrains','annotations','13.0'),('org.jetbrains.intellij.deps','trove4j','1.0.20200330'),('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.8.0'),('com.google.code.gson','gson','2.13.1'),('org.json','json','20240303')]
JAVA=r'''
import java.nio.file.*;import org.jetbrains.kotlin.cli.jvm.compiler.*;import org.jetbrains.kotlin.config.*;import org.jetbrains.kotlin.com.intellij.openapi.util.Disposer;import org.jetbrains.kotlin.com.intellij.psi.*;import org.jetbrains.kotlin.psi.*;
class KotlinSyntax {
 static int errors=0;
 public static void main(String[]args)throws Exception{
  var disposable=Disposer.newDisposable();try{
   var environment=KotlinCoreEnvironment.createForProduction(disposable,new CompilerConfiguration(),EnvironmentConfigFiles.JVM_CONFIG_FILES);
   var factory=new KtPsiFactory(environment.getProject(),false);
   for(String name:args){var file=factory.createFile(name,Files.readString(Path.of(name)));file.accept(new PsiRecursiveElementWalkingVisitor(){public void visitErrorElement(PsiErrorElement error){errors++;System.err.println(name+":"+error.getTextOffset()+": "+error.getErrorDescription());}});}
   if(errors!=0)throw new IllegalStateException("Kotlin syntax errors: "+errors);
   System.out.println("Kotlin PSI syntax PASS files="+args.length);
  }finally{Disposer.dispose(disposable);}
 }
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cache',type=Path,required=True);p.add_argument('files',nargs='+');a=p.parse_args();a.cache.mkdir(parents=True,exist_ok=True)
 jars=[];inventory=[]
 locked={x['artifact']:x for x in json.loads(Path(__file__).with_name('catalog-results-dependencies.json').read_text())}
 for group,artifact,version in DEPENDENCIES:
  relative=group.replace('.','/')+'/'+artifact+'/'+version+'/'+artifact+'-'+version+'.jar';url=BASE+relative;path=a.cache/Path(relative).name
  if not path.exists():
   with urllib.request.urlopen(url,timeout=30) as r:data=r.read(75*1024*1024+1)
   if len(data)>75*1024*1024:raise ValueError('Dependency exceeds bound')
   with urllib.request.urlopen(url+'.sha1',timeout=30) as r:expected=r.read(128).decode().strip()
   if hashlib.sha1(data).hexdigest()!=expected:raise ValueError('Repository checksum differs')
   path.write_bytes(data)
  data=path.read_bytes();identity=group+':'+artifact+':'+version;digest=hashlib.sha256(data).hexdigest()
  if locked[identity]['source']!=url or locked[identity]['sha256']!=digest:raise ValueError('Pinned dependency checksum differs: '+identity)
  jars.append(str(path));inventory.append({'artifact':identity,'source':url,'sha256':digest})
 source=a.cache/'KotlinSyntax.java';source.write_text(JAVA)
 (a.cache/'dependencies.json').write_text(json.dumps(inventory,indent=2)+'\n')
 result=subprocess.run(['java','--class-path',':'.join(jars),str(source),*a.files],timeout=60)
 raise SystemExit(result.returncode)
if __name__=='__main__':main()
