#!/usr/bin/env python3
"""Data-only Java integer/byte-array parser; no eval, classes or native execution."""
import argparse,json,re
from pathlib import Path
TOKEN=re.compile(r'>>>|>>|<<|(?:this\.)?[A-Za-z_$][\w$]*|\d+|[()\[\]~^|&+*/%,-]')
PREC={'|':1,'^':2,'&':3,'<<':4,'>>':4,'>>>':4,'+':5,'-':5,'*':6,'/':6,'%':6}
def signed(x):
    x&=0xffffffff;return x if x<0x80000000 else x-0x100000000
class Expr:
    def __init__(self,s,env):
        self.ts=TOKEN.findall(s);self.i=0;self.env=env
        if ''.join(self.ts)!=re.sub(r'\s+','',s):raise ValueError('Unsupported expression')
    def take(self):t=self.ts[self.i];self.i+=1;return t
    def one(self):
        t=self.take()
        if t in ('~','-','+'):
            v=self.one();return signed(~v if t=='~' else -v if t=='-' else v)
        if t=='(':
            if self.ts[self.i] in ('byte','int') and self.ts[self.i+1]==')':
                cast=self.take();self.take();v=self.one();return (v+128)%256-128 if cast=='byte' else signed(v)
            v=self.parse();assert self.take()==')';return v
        v=int(t) if t.isdecimal() else self.env[t]
        if self.i<len(self.ts) and self.ts[self.i]=='[':
            self.take();n=self.parse();assert self.take()==']';v=v[n]
        return v
    def parse(self,minimum=1):
        v=self.one()
        while self.i<len(self.ts) and PREC.get(self.ts[self.i],0)>=minimum:
            op=self.take();w=self.parse(PREC[op]+1)
            if op=='>>>':v=(v&0xffffffff)>>(w&31)
            elif op=='>>':v=signed(v)>>(w&31)
            elif op=='<<':v=v<<(w&31)
            elif op=='^':v=v^w
            elif op=='|':v=v|w
            elif op=='&':v=v&w
            elif op=='+':v=v+w
            elif op=='-':v=v-w
            elif op=='*':v=v*w
            elif op=='/':v=int(v/w)
            elif op=='%':v=v%w
            v=signed(v)
        return v
def evaluate(s,env):
    p=Expr(s,env);v=p.parse()
    if p.i!=len(p.ts):raise ValueError('Trailing expression')
    return v
def main():
    p=argparse.ArgumentParser();p.add_argument('private',type=Path);a=p.parse_args();d=a.private;values=[];failures=[];out=d/'literals';out.mkdir(exist_ok=True,mode=0o700)
    for original in d.glob('jadx*/sources/**/*.java'):
        if not ('netfree/' in str(original) or '/t5p215r1/' in str(original)):continue
        source=d/'decoded'/original.relative_to(d);source=source if source.exists() else original;text=source.read_text()
        classes=list(re.finditer(r'^    (?:[\w ]+ )?class (\w+)[^{]*\{',text,re.M));mapping={}
        for i,m in enumerate(classes):
            block=text[m.end():classes[i+1].start() if i+1<len(classes) else len(text)];ret=re.search(r'return new String\(new byte\[\]\{(.*?)\}\)',block,re.S)
            if not ret:continue
            env={}
            for line in block[:ret.start()].splitlines():
                item=re.search(r'^\s*(?:(byte\[\]|byte|int) )?((?:this\.)?\w+) = (.*?);',line)
                if not item:continue
                kind,name,expr=item.groups()
                try:
                    if expr.startswith('new byte[]{') and expr.endswith('}'):value=[evaluate(v,env) for v in expr[11:-1].split(',')]
                    elif expr in env:value=env[expr]
                    else:value=evaluate(expr,env)
                    if kind=='byte':value=(value+128)%256-128
                    env[name]=value
                except (ValueError,KeyError,IndexError,AssertionError,TypeError):continue
            try:value=bytes(evaluate(v,env)&255 for v in ret[1].split(',')).decode('utf-8')
            except (ValueError,KeyError,IndexError,AssertionError,TypeError,UnicodeError) as e:
                failures.append({'path':str(original.relative_to(d)),'class':m[1],'error':type(e).__name__});continue
            mapping[m[1]]=value;values.append({'path':str(original.relative_to(d)),'class':m[1],'value':value})
        for name,value in mapping.items():text=re.sub(r'new '+name+r'\([^()]*\)\.toString\(\)',lambda _:json.dumps(value,ensure_ascii=False),text)
        target=out/original.relative_to(d);target.parent.mkdir(exist_ok=True,parents=True);target.write_text(text);target.chmod(0o600)
    (d/'arrays.json').write_text(json.dumps(values,ensure_ascii=False,indent=2));(d/'arrays.json').chmod(0o600)
    report={'recovered':len(values),'unresolved':len(failures),'failures':failures};(d/'arrays-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='failures'}))
if __name__=='__main__':main()
