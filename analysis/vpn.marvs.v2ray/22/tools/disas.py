import sys
from capstone import *
data = open('arm64/lib/arm64-v8a/libgojni.so','rb').read()
TEXT_FILE_OFF = 0xf29340
def dis(start, end, out):
    code = data[TEXT_FILE_OFF+start:TEXT_FILE_OFF+end]
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    with open(out,'w') as f:
        for ins in md.disasm(code, start):
            f.write(f'{ins.address:x}: {ins.mnemonic} {ins.op_str}\n')
    print(out, 'lines:', sum(1 for _ in open(out)))
if __name__ == '__main__':
    dis(int(sys.argv[1],0), int(sys.argv[2],0), sys.argv[3])
