import os
os.environ["LOGURU_LEVEL"] = "ERROR"
from androguard.misc import AnalyzeDex
h, d, dx = AnalyzeDex('apk/base/classes2.dex')
print('classes:', len(d.get_classes()))
for s in dx.get_strings():
    v = s.get_value()
    if 'pastebin' in v or 'tk.js' in v:
        print('STRING:', v)
        for _, meth in dx.find_usage(v):
            print('  used by:', meth.class_name, meth.name, meth.descriptor)
print('--- checkUpdate class ---')
for c in d.get_classes():
    if 'checkUpdate' in c.get_name():
        print('CLASS:', c.get_name())
        for m in c.get_methods():
            print('  METHOD:', m.get_name(), m.get_descriptor())
print('--- tknetwork classes with Update/Server/Config/Catalog/Download ---')
for c in d.get_classes():
    n = c.get_name()
    if 'tknetwork' in n and any(k in n for k in ('Update','Server','Config','Catalog','Download','Export','Hotshare','Import')):
        print(' ', n)
