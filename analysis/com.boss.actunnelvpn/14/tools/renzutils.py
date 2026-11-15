#!/usr/bin/env python3
"""Dump RenzUtils class bytecode + find callers of RenzUtils.decrypt/encrypt."""
import sys, zipfile
sys.path.insert(0, '/home/hatch/workspace/http-custom-update/venv/lib/python3.12/site-packages')
from androguard.core.dex import DEX

apk = '/home/hatch/workspace/catalogs/actunnel/apk/com.boss.actunnelvpn.apk'
z = zipfile.ZipFile(apk)
TARGET = 'Lrenz/javacodez/vpn/utils/RenzUtils;'
out = open('/home/hatch/workspace/catalogs/actunnel/work/renzutils.txt', 'w')

for dexname in sorted(n for n in z.namelist() if n.endswith('.dex')):
    d = DEX(z.read(dexname))
    for cls in d.get_classes():
        name = cls.get_name()
        # dump RenzUtils fully
        if name == TARGET:
            out.write(f'== CLASS {name} in {dexname}\n')
            for m in cls.get_methods():
                out.write(f'-- METHOD {m.get_name()}{m.get_descriptor()} flags={m.get_access_flags_string()}\n')
                code = m.get_code()
                if code is None:
                    out.write('   (no code)\n')
                    continue
                for ins in code.get_bc().get_instructions():
                    out.write(f'   {ins.get_name():24s} {ins.get_output()}\n')
        # find callers of RenzUtils.decrypt / encrypt / initializeApp
        for m in cls.get_methods():
            code = m.get_code()
            if code is None:
                continue
            for ins in code.get_bc().get_instructions():
                o = ins.get_output()
                if 'RenzUtils;->decrypt' in o or 'RenzUtils;->encrypt' in o or 'RenzUtils;->initializeApp' in o:
                    out.write(f'CALLER {name} {m.get_name()}{m.get_descriptor()} :: {ins.get_name()} {o}\n')
out.close()
print('done')
