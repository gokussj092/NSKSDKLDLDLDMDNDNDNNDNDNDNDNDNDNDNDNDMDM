#!/usr/bin/env python3
"""Deobfuscate com.panda912.muddy.ObfuscatedString long[] values (Java Random LCG)."""
import sys

MASK48 = (1 << 48) - 1
MULT = 0x5DEECE66D
ADD = 0xB

class JavaRandom:
    def __init__(self, seed):
        # seed is signed 64-bit java long
        self.seed = ((seed ^ MULT) & MASK48)
    def next(self, bits):
        self.seed = (self.seed * MULT + ADD) & MASK48
        return self.seed >> (48 - bits)
    def next_long(self):
        # java.util.Random.nextLong() == ((long) next(32) << 32) + next(32)
        # where next(32) is a SIGNED int: the low half is added signed, so
        # when its top bit is set the result is 2**32 less than (hi<<32)|lo.
        hi = self.next(32)
        lo = self.next(32)
        if lo >= (1 << 31):
            lo -= (1 << 32)
        return to_signed64((hi << 32) + lo)

def to_signed64(v):
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >= (1 << 63) else v

def deobfuscate(longs):
    longs = [to_signed64(x) for x in longs]
    rnd = JavaRandom(longs[0])
    buf = bytearray()
    for val in longs[1:]:
        x = (val ^ rnd.next_long()) & ((1 << 64) - 1)
        for _ in range(8):
            buf.append(x & 0xFF)
            x >>= 8
    while buf and buf[-1] == 0:
        buf.pop()
    return bytes(buf).decode('utf-8')

if __name__ == '__main__':
    tests = {
        'UtilsKey.key': [-5936219325704156598, -2616245643709710320],
        'Parser.a password': [260353295430736385, 3535111702893634698],
        'AESHelper.TAG': [1966459513154949909, -4517174252800385594],
        'AESHelper.AES_MODE': [-1270381110403954725, 4163199488994536413, -4961096277951323070, -1693765181508183669],
        'AESHelper.CHARSET': [-8442255935865376357, -1995173925104491255],
        'AESHelper.HASH_ALGORITHM': [2686336998359343244, 5615683688986547758],
        'AESHelper key alg': [585815599524798283, 2824538934229930675],
    }
    for name, longs in tests.items():
        try:
            print(f"{name}: {deobfuscate(longs)!r}")
        except Exception as e:
            print(f"{name}: ERROR {e}")
