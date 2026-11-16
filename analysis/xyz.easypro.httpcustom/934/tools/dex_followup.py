"""Bounded original DEX outline for local format/recipient code investigation."""
import argparse,json,re,zipfile
from pathlib import Path
from loguru import logger
logger.remove()
from androguard.core.dex import DEX

def main():
    p=argparse.ArgumentParser();p.add_argument('apk',type=Path);p.add_argument('--class-pattern')
    p.add_argument('--dump-method')
    a=p.parse_args();found=[]
    with zipfile.ZipFile(a.apk) as z:
        for name in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex',name):continue
            dex=DEX(z.read(name))
            for c in dex.get_classes():
                if a.class_pattern and re.search(a.class_pattern,c.get_name()):
                    if a.dump_method:
                        for m in c.get_methods():
                            if m.get_name()==a.dump_method:
                                found.append({'class':c.get_name(),'method':m.get_name(),
                                  'instructions':[ins.get_name()+' '+ins.get_output() for ins in m.get_instructions()]})
                        continue
                    found.append({'class':c.get_name(),'fields':[{'name':f.get_name(),'type':f.get_descriptor()} for f in c.get_fields()],
                        'methods':[{'name':m.get_name(),'descriptor':m.get_descriptor(),'access':m.get_access_flags_string()} for m in c.get_methods()]})
                    continue
                if a.class_pattern:continue
                for m in c.get_methods():
                    for ins in m.get_instructions():
                        out=ins.get_output()
                        if any(x in out for x in ('KeyPairGenerator;','KeyGenParameterSpec','KeyStore;','OAEPParameterSpec')):
                            found.append({'class':c.get_name(),'method':m.get_name(),'descriptor':m.get_descriptor(),
                                          'instruction':ins.get_name()+' '+out})
    print(json.dumps(found,indent=2))
if __name__=='__main__':main()
