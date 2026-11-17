"""XXTEA generico (mismo algoritmo que el catalogo Fx: delta 0x9E5729B1,
palabras little-endian, longitud original en la ultima palabra).

Codigo generico sin claves de formato: las pruebas pasan claves de
PRUEBA generadas aqui mismo. El descifrado con la clave real esta
cubierto por la reproduccion del empaquetado desde base.apk
(Fx_Tunnel.py --apks, ver RESULTS.md).
"""
import struct

MASK = 0xFFFFFFFF
DELTA = (-1638454863) & MASK  # 0x9E5729B1


def _mx(total, y, z, position, e, key):
    return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((total ^ y) + (key[(position & 3) ^ e] ^ z))) & MASK


def encrypt(data: bytes, key16: bytes) -> bytes:
    key = struct.unpack("<4I", key16[:16].ljust(16, b"\0"))
    count = (len(data) + 3) // 4 + 1
    values = list(struct.unpack("<%dI" % count,
                                data.ljust((count - 1) * 4, b"\0") + struct.pack("<I", len(data))))
    total = 0
    rounds = 6 + 52 // count
    for _ in range(rounds):
        total = (total + DELTA) & MASK
        e = (total >> 2) & 3
        z = values[-1]
        for position in range(count):
            y = values[(position + 1) % count]
            values[position] = (values[position] + _mx(total, y, z, position, e, key)) & MASK
            z = values[position]
    return struct.pack("<%dI" % count, *values)


def decrypt(data: bytes, key16: bytes) -> bytes:
    key = struct.unpack("<4I", key16[:16].ljust(16, b"\0"))
    values = list(struct.unpack("<%dI" % (len(data) // 4), data))
    count = len(values)
    total = ((6 + 52 // count) * DELTA) & MASK
    y = values[0]
    while total:
        e = (total >> 2) & 3
        for position in range(count - 1, 0, -1):
            values[position] = (values[position] - _mx(total, y, values[position - 1], position, e, key)) & MASK
            y = values[position]
        values[0] = (values[0] - _mx(total, y, values[-1], 0, e, key)) & MASK
        y = values[0]
        total = (total - DELTA) & MASK
    length = values[-1]
    return struct.pack("<%dI" % (count - 1), *values[:-1])[:length]
