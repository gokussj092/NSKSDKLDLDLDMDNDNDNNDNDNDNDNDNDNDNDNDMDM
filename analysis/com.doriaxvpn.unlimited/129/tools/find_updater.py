#!/usr/bin/env python3
"""Find exact updater references across DEX without executing APK code."""
import argparse,json
from pathlib import Path
from loguru import logger
from androguard.core.dex import DEX
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('dex_directory',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    logger.remove();out=[]
    needles=('Ln61;->e(', 'Lbl;->a', 'Lur;->g(', 'raw.githubusercontent.com/soportecrisdev/Gen/main/Update')
    for f in sorted(a.dex_directory.glob('*.dex')):
        dex=DEX(f.read_bytes())
        for cls in dex.get_classes():
            for method in cls.get_methods():
                instructions=[{'opcode':i.get_name(),'operands':i.get_output()} for i in method.get_instructions()]
                if any(any(n in i['operands'] for n in needles) for i in instructions):
                    out.append({'dex':f.name,'class':cls.get_name(),'method':method.get_name(),'descriptor':method.get_descriptor(),'instructions':instructions})
    a.output.write_text(json.dumps(out,ensure_ascii=True,indent=2)+'\n');a.output.chmod(0o600)
    print(json.dumps([{'dex':r['dex'],'class':r['class'],'method':r['method'],'instructions':len(r['instructions'])} for r in out]))
if __name__=='__main__':main()
