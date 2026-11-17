#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Codec baybayin de M Light (SIN claves): pares de caracteres = 1 byte.

El alfabeto de 17 caracteres es un campo estatico publico del metodo
(clase AESCrypt); este modulo solo codifica/decodifica pares y NO
contiene ninguna clave, URL ni material criptografico. La clave AES
vive unicamente en el script operativo.
"""
ALPHABET = "".join(chr(c) for c in (
    0x6e6, 0x1711, 0x1710, 0x170f, 0x170e, 0x170c, 0x1708, 0x1707, 0x1706,
    0x1702, 0x1701, 0x1700, 0x170b, 0x170a, 0x1709, 0x1705, 0x1704))


class BaybayinError(ValueError):
    pass


def baybayin_decode(text):
    """Pares de caracteres baybayin -> bytes (cada par = 1 byte)."""
    text = "".join(text.split())
    if len(text) % 2:
        raise BaybayinError("texto baybayin con longitud impar: %d" % len(text))
    idx = {c: i for i, c in enumerate(ALPHABET)}
    out = bytearray()
    for i in range(0, len(text), 2):
        hi = idx.get(text[i])
        lo = idx.get(text[i + 1])
        if hi is None or lo is None:
            raise BaybayinError("caracter fuera del alfabeto en posicion %d" % i)
        out.append(hi * 16 + lo)
    return bytes(out)


def baybayin_encode(data):
    """Bytes -> pares de caracteres baybayin."""
    return "".join(ALPHABET[b >> 4] + ALPHABET[b & 0x0f] for b in data)
