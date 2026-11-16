"""Trace the original RSA parameter initializer with public/modelled JVM objects.

No private key is created or loaded, and unknown Java calls stop the model.
"""
import argparse,json,struct
from jni_format_probe import Probe

def main():
    p=argparse.ArgumentParser();p.add_argument('library');a=p.parse_args()
    e=Probe(a.library);e.call(e.image.names['JNI_OnLoad'][0],e.vm,0,limit=5000000)
    # Grounded from the original DEX: oeynnivvrnts0(858), not dispatcher 2.
    e.call(0xa0f614,e.env,0,858,limit=10000000)
    registration=next(x for x in e.registrations if x[0]=='dev/epro/r0/E5538123785991428492')
    fn=int(next(x[2] for x in registration[1] if x[0]=='vuhmsqepstoy'),16)
    original=e.jni;constructed=[]
    def value(v):return e.objects.get(v,v)
    def args(ptr):return [value(v) for v in struct.unpack('<8Q',e.read(ptr,64))]
    def jni(i):
        aa=[e.reg(k) for k in range(8)];obj=value(aa[1]);member=value(aa[2]);name=member[0] if isinstance(member,list) else None
        if i==27:return e.finish(e.obj({'__cls__':obj}))
        if i==32:
            cls=value(aa[2]);actual=obj.get('__cls__',obj.get('class')) if isinstance(obj,dict) else 'java/lang/Integer' if isinstance(obj,int) else 'java/lang/String' if isinstance(obj,str) else '[B' if isinstance(obj,bytes) else '[Ljava/lang/Object;'
            return e.finish(int(cls==actual or cls=='java/lang/Object'))
        if i==31:
            cls=obj.get('__cls__',obj.get('class')) if isinstance(obj,dict) else 'java/lang/Integer' if isinstance(obj,int) else 'java/lang/String' if isinstance(obj,str) else '[B' if isinstance(obj,bytes) else '[Ljava/lang/Object;'
            return e.finish(e.obj(cls))
        if i in (49,51,52,54,55,57) and name in ('intValue','booleanValue','longValue') and isinstance(obj,int):
            return e.finish(obj)
        if i in (141,143) and obj=='java/util/Arrays' and name=='fill':
            vals=struct.unpack('<8Q',e.read(aa[3],64)) if i==143 else tuple(aa[3:]+[0]*3)
            target=e.objects[vals[0]]
            if member[1]=='([Ljava/lang/Object;Ljava/lang/Object;)V':target[:]=[vals[1]]*len(target);return e.finish()
            raise ValueError('Unmodelled Arrays.fill overload')
        if i==171:return e.finish(len(obj))
        if i==172:return e.finish(e.obj([aa[3]]*aa[1]))
        if i==173:return e.finish(obj[aa[2]])
        if i==174:obj[aa[2]]=aa[3];return e.finish()
        if i in (28,29,30):
            vals=args(aa[3]) if i in (29,30) else [value(v) for v in aa[3:]]
            if obj=='java/lang/String':
                if isinstance(vals[0],bytes):return e.finish(e.obj(vals[0].decode()))
                raise ValueError('Unmodelled String constructor '+repr(vals))
            result={'class':obj,'constructor':member,'arguments':vals[:4]}
            constructed.append(result);return e.finish(e.obj(result))
        if i in (34,36,114,116):
            vals=args(aa[3]) if i in (36,116) else [value(v) for v in aa[3:]]
            if name=='intern':return e.finish(aa[1])
            if name=='valueOf' and obj in ('java/lang/Integer','java/lang/Boolean','java/lang/Long'):
                return e.finish(e.obj(vals[0]))
            if name in ('intValue','booleanValue','longValue') and isinstance(obj,int):return e.finish(obj)
            if name=='getBytes' and isinstance(obj,str):return e.finish(e.obj(obj.encode()))
            if name=='getClass':return e.finish(e.obj(obj.get('class','java/lang/Object') if isinstance(obj,dict) else 'java/lang/String'))
            raise ValueError('Unmodelled Java call '+repr((obj,member,vals[:4])))
        if i in (61,63,64,66,93,95,97,99,101):
            if i in (61,63,64,66,93):
                mm=value(aa[3]) if i==93 else member
                if isinstance(mm,list) and mm[0]=='<init>':
                    vals=args(aa[4]) if i==93 else args(aa[3]) if i in (63,66) else [value(x) for x in aa[3:]]
                    if isinstance(obj,dict):
                        obj.update(constructor=mm,arguments=vals[:5])
                        if obj.get('__cls__','').startswith(('javax/crypto/spec/','java/security/spec/')):constructed.append(obj.copy())
                    return e.finish()
            raise ValueError('Unmodelled field/void call '+repr((i,obj,member)))
        return original(i)
    e.jni=jni;array=e.obj([0]*13);steps=[]
    try:
        for n in range(12):
            code=e.call(fn,e.env,0,array,limit=10000000)
            steps.append({'code':code,'value':value(e.objects[array][1])})
            if code==0:break
    except Exception as error:print(json.dumps({'error':str(error),'steps':steps,'constructed':constructed,'recent_members':e.logs[-12:]},default=str,indent=2));return
    print(json.dumps({'steps':steps,'constructed':constructed},default=str,indent=2))
if __name__=='__main__':main()
