"""XXTEA decrypt as used by ASL Tunnel (LyF0.k), custom delta 0x9A7393B4.
Envelope (Lfu0.a): Base64 -> XXTEA decrypt, key = first 16 bytes of
UTF-8('ㅤ' U+3164 x33) = E1 85 A4 x5 + E1. Plaintext length stored in last word.
"""
import base64, struct

DELTA = 0x9A7393B4
MASK = 0xFFFFFFFF

def _mx(z, y, s, p, e, k):
    return (((((z >> 5) ^ ((y << 2) & MASK)) & MASK) + (((y >> 3) ^ ((z << 4) & MASK)) & MASK)) & MASK) ^ \
           (((s ^ y) + ((k[(p & 3) ^ e] ^ z) & MASK)) & MASK)

def xxtea_decrypt(data: bytes, key16: bytes):
    if len(data) == 0:
        return b''
    n = len(data) // 4
    v = list(struct.unpack('<%dI' % n, data[:n*4]))
    k = list(struct.unpack('<4I', key16[:16].ljust(16, b'\x00')))
    rounds = 6 + 52 // n
    s = (rounds * DELTA) & MASK
    y = v[0]
    while s != 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(z, y, s, p, e, k)) & MASK
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(z, y, s, 0, e, k)) & MASK
        y = v[0]
        s = (s - DELTA) & MASK
    raw = struct.pack('<%dI' % n, *v)
    ln = v[n - 1]
    if ln < len(raw) - 7 or ln > len(raw) - 4:
        return None
    return raw[:ln]

KEY16 = bytes.fromhex('e385a4' * 5 + 'e3')

def decrypt_alt(blob_text: str) -> bytes:
    raw = base64.b64decode(''.join(blob_text.split()))
    return xxtea_decrypt(raw, KEY16)

if __name__ == '__main__':
    txt = open('live_alt.txt').read()
    print("blob chars:", len(txt), "newlines:", txt.count('\n'))
    out = decrypt_alt(txt)
    if out is None:
        print("DECRYPT FAILED (bad length word)")
    else:
        print("decrypted bytes:", len(out))
        print(out[:500])
        open('live_alt_decrypted.json', 'wb').write(out)
