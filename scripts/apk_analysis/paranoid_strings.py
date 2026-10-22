#!/usr/bin/env python3
"""Resolve literal LSParanoid getString(long) calls in JADX output, offline."""
from __future__ import annotations
import argparse
import base64
from pathlib import Path
import re
import subprocess
import tempfile
import json

# Pure arithmetic transcribed from DeobfuscatorHelper/RandomHelper. No APK code runs.
JAVA = r'''
import java.io.*;import java.nio.charset.StandardCharsets;import java.util.*;
class Strings {
 static String chunk(String encoded){byte[] b=Base64.getDecoder().decode(encoded);char[] c=new char[b.length/2];for(int i=0;i<c.length;i++)c[i]=(char)(((b[2*i]&255)<<8)|(b[2*i+1]&255));return new String(c);}
 static final String[] chunks = CHUNKS;
 static short rotl(short x,int n){return (short)((x>>> (32-n))|(x<<n));}
 static long seed(long x){long a=(x^(x>>>33))*7109453100751455733L;return ((a^(a>>>28))*-3808689974395783757L)>>>32;}
 static long next(long x){short a=(short)x,b=(short)(x>>>16),c=(short)(rotl((short)(a+b),9)+a),d=(short)(b^a),e=(short)(rotl(a,13)^d^(d<<5));return ((rotl(d,10)|((long)c<<16))<<16)|(long)e;}
 static long at(int i,long state){return ((long)chunks[i/8191].charAt(i%8191)<<32)^next(state);}
 static String decode(long id){long a=next(seed(id&0xffffffffL)),b=next(a);int p=(int)((id>>>32)^((a>>>32)&65535)^((b>>>16)&-65536));long s=at(p,b);int n=(int)((s>>>32)&65535);char[]out=new char[n];for(int i=0;i<n;i++){s=at(p+i+1,s);out[i]=(char)((s>>>32)&65535);}return new String(out);}
 public static void main(String[]args)throws Exception{if(args.length>0){long seed=Long.parseLong(args[0]),a=next(seed(seed)),b=next(a);int mask=(int)(((a>>>32)&65535)^((b>>>16)&-65536));int total=0;for(String chunk:chunks)total+=chunk.length();for(int i=0;i<total;){long id=((long)(i^mask)<<32)|(seed&0xffffffffL);String value=decode(id);if(value.length()>total-i-1)throw new IllegalArgumentException("Invalid chunk inventory");System.out.println(i+"\t"+Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)));i+=value.length()+1;}return;}var r=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));String s;while((s=r.readLine())!=null)System.out.println(Base64.getEncoder().encodeToString(decode(Long.parseLong(s)).getBytes(StandardCharsets.UTF_8)));}
}
'''


def chunk_expression(literal: str) -> str:
    """Parse data, then serialize UTF-16 units; never compile input source text."""
    s=literal[1:-1];out=[];i=0
    escapes={'b':'\b','t':'\t','n':'\n','f':'\f','r':'\r','"':'"',"'":"'",'\\':'\\'}
    while i<len(s):
        c=s[i];i+=1
        if c!='\\':out.append(c);continue
        c=s[i];i+=1
        if c in escapes:out.append(escapes[c])
        elif c=='u':
            while i<len(s) and s[i]=='u':i+=1
            if not re.fullmatch('[0-9a-fA-F]{4}',s[i:i+4]):raise ValueError('Invalid Unicode escape')
            out.append(chr(int(s[i:i+4],16)));i+=4
        elif c in '01234567':
            digits=c;limit=3 if c in '0123' else 2
            while len(digits)<limit and i<len(s) and s[i] in '01234567':digits+=s[i];i+=1
            out.append(chr(int(digits,8)))
        else:raise ValueError('Unsupported Java string escape')
    encoded=base64.b64encode(''.join(out).encode('utf-16-be',errors='surrogatepass')).decode('ascii')
    return 'chunk("'+encoded+'")'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path,help='JADX source root')
    p.add_argument('chunks_class',type=Path,help='Deobfuscator class containing the string chunks')
    p.add_argument('output',type=Path,help='Private output directory, outside source')
    p.add_argument('--inventory',action='store_true',help='Also recover all chunk strings when all literal IDs share one seed')
    p.add_argument('--chunk-field',default='chunks',help='Confirmed renamed chunk field')
    p.add_argument('--method',default='getString',help='Confirmed renamed literal decoder method')
    a=p.parse_args();source=a.source.resolve();output=a.output.resolve()
    if output==source or source in output.parents or output in source.parents:
        p.error('Source and output directories must be separate, without nesting')
    text=a.chunks_class.read_text('utf-8')
    if not all(re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*',v) for v in (a.chunk_field,a.method)):
        p.error('Expected Java identifiers for field and method')
    match=re.search(r'\b'+re.escape(a.chunk_field)+r'\s*=\s*new String\[\]\{(.*?)\};',text,re.S)
    if not match:raise ValueError('No LSParanoid chunks found')
    literal=re.compile(r'"(?:\\.|[^"\\])*"',re.S)
    parts=literal.findall(match[1]);remainder=literal.sub('',match[1])
    if not parts or remainder.strip(' \r\n\t,'):raise ValueError('Unsupported chunk expression')
    class_name=a.chunks_class.stem
    call=re.compile(re.escape(class_name)+r'\.'+re.escape(a.method)+r'\((-?\d+)L\)')
    files=[];ids=[]
    for f in source.rglob('*.java'):
        s=f.read_text('utf-8');found=call.findall(s)
        if found:files.append((f,s));ids.extend(found)
    ids=list(dict.fromkeys(ids))
    if not ids:raise ValueError('No literal getString calls found')
    with tempfile.TemporaryDirectory(prefix='spdecode-paranoid-') as tmp:
        path=Path(tmp)/'Strings.java';path.write_text(JAVA.replace('CHUNKS','new String[]{'+','.join(map(chunk_expression,parts))+'}'),'utf-8')
        r=subprocess.run(['java',str(path)],input='\n'.join(ids)+'\n',text=True,capture_output=True,timeout=60,check=True)
        values=r.stdout.splitlines()
        inventory=[]
        if a.inventory:
            seeds={int(i)&0xffffffff for i in ids}
            if len(seeds)!=1:raise ValueError('Inventory requires one shared seed')
            r=subprocess.run(['java',str(path),str(next(iter(seeds)))],text=True,capture_output=True,timeout=60,check=True)
            for line in r.stdout.splitlines():
                offset,value=line.split('\t',1)
                inventory.append({'offset':int(offset),'value':base64.b64decode(value,validate=True).decode('utf-8')})
    if len(values)!=len(ids):raise ValueError('Incomplete Java output')
    decoded={i:base64.b64decode(v,validate=True).decode('utf-8') for i,v in zip(ids,values)}
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    for f,s in files:
        target=output/f.relative_to(source);target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(call.sub(lambda m:json.dumps(decoded[m[1]],ensure_ascii=True),s),'utf-8');target.chmod(0o600)
    if a.inventory:
        target=output/'string-inventory.json';target.write_text(json.dumps(inventory,ensure_ascii=True,indent=2),'utf-8');target.chmod(0o600)
    print(json.dumps({'resolvedStrings':len(ids),'sourceFiles':len(files),'inventoryStrings':len(inventory)}))

if __name__=='__main__':main()
