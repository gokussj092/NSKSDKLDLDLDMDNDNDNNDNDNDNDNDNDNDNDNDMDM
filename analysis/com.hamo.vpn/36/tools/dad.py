import sys
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerDAD

dex = DEX(open('apk/base/classes.dex','rb').read())
print("DEX loaded", file=sys.stderr)
vmx = Analysis(dex)
print("Analysis created", file=sys.stderr)
dad = DecompilerDAD(dex, vmx)
target_class = sys.argv[1]
for cls in dex.get_classes():
    if target_class in cls.get_name():
        print("="*20, cls.get_name())
        for m in cls.get_methods():
            print("--- method:", m.get_name(), m.get_descriptor())
            try:
                ma = vmx.get_method(m)
                src = dad.get_source_method(ma) if hasattr(dad, 'get_source_method') else None
                print(src)
            except Exception as e:
                print("DECOMPILE FAIL:", type(e).__name__, e)
