import struct, sys
from elftools.elf.elffile import ELFFile

def parse(path):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        data = open(path, 'rb').read()
    magic = bytes.fromhex('f1ffffff00000408')
    idx = data.find(magic)
    print('pclntab header at file offset', hex(idx))
    if idx < 0:
        sys.exit(1)
    vals = struct.unpack_from('<8Q', data, idx + 8)
    nfunc, nfiles, textStart, funcnameOff, cuOff, filetabOff, pctabOff, pclnOff = vals
    print('nfunc', nfunc, 'textStart', hex(textStart))
    ft_off = idx + pclnOff
    funcs = []
    for i in range(nfunc):
        entryoff, funcoff = struct.unpack_from('<II', data, ft_off + i * 8)
        name_ptr = struct.unpack_from('<i', data, idx + pclnOff + funcoff + 4)[0]
        name_off = idx + funcnameOff + name_ptr
        end = data.find(b'\x00', name_off)
        name = data[name_off:end].decode('utf-8', 'replace')
        addr = textStart + entryoff
        funcs.append((addr, name))
    return funcs

if __name__ == '__main__':
    funcs = parse(sys.argv[1])
    with open('gojni-funcs.txt', 'w') as f:
        for a, n in funcs:
            f.write(f'{a:#x}\t{n}\n')
    print('wrote', len(funcs), 'functions')
