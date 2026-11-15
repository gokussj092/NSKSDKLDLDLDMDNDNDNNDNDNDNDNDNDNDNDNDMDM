"""Criptografia generica extraida de RH_Tunnel_Lite.py.

AES-CBC + empaquetado chino de 12 bits + XXTEA (delta no estandar) +
enlaces c_01. Sin claves de formato, sin tokens, sin endpoints: la clave
de texto la aporta quien llama como parametro (ver tests/test_method.py).
El delta XXTEA y el prefijo del blob son parametros del algoritmo
documentados en el README de origen. Origen: script operativo
~/workspace/catalogs/rhtunnel/RH_Tunnel_Lite.py (SHA-256 en MANIFEST.json).
"""
import base64
import hashlib
import struct

_XXTEA_DELTA = 772515655
_PREFIX = "Telegram@noob_xman"

# AES rapido si pycryptodome esta disponible; si no, implementacion pura
# incluida abajo (misma salida, mas lenta). El self-test verifica ambas.
try:
    from Crypto.Cipher import AES as _CRYPTO_AES
except Exception:
    _CRYPTO_AES = None


def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(a):
    if a == 0:
        return 0
    r = 1
    for _ in range(254):
        r = _gf_mul(r, a)
    return r


def _build_sboxes():
    sbox = []
    inv_sbox = [0] * 256
    for i in range(256):
        inv = _gf_inv(i)
        s = inv
        for shift in (1, 2, 3, 4):
            s ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        s ^= 0x63
        s &= 0xFF
        sbox.append(s)
        inv_sbox[s] = i
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _build_sboxes()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key):
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    return w, nr


def _add_round_key(state, w, rnd):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= w[rnd * 4 + c][r]


def _sub_bytes(state, box):
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]


def _shift_rows(state, inverse=False):
    for r in range(1, 4):
        row = [state[r][c] for c in range(4)]
        n = r if not inverse else 4 - r
        row = row[n:] + row[:n]
        for c in range(4):
            state[r][c] = row[c]


def _mix_columns(state, inverse=False):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        if not inverse:
            state[0][c] = _gf_mul(a[0], 2) ^ _gf_mul(a[1], 3) ^ a[2] ^ a[3]
            state[1][c] = a[0] ^ _gf_mul(a[1], 2) ^ _gf_mul(a[2], 3) ^ a[3]
            state[2][c] = a[0] ^ a[1] ^ _gf_mul(a[2], 2) ^ _gf_mul(a[3], 3)
            state[3][c] = _gf_mul(a[0], 3) ^ a[1] ^ a[2] ^ _gf_mul(a[3], 2)
        else:
            state[0][c] = _gf_mul(a[0], 14) ^ _gf_mul(a[1], 11) ^ _gf_mul(a[2], 13) ^ _gf_mul(a[3], 9)
            state[1][c] = _gf_mul(a[0], 9) ^ _gf_mul(a[1], 14) ^ _gf_mul(a[2], 11) ^ _gf_mul(a[3], 13)
            state[2][c] = _gf_mul(a[0], 13) ^ _gf_mul(a[1], 9) ^ _gf_mul(a[2], 14) ^ _gf_mul(a[3], 11)
            state[3][c] = _gf_mul(a[0], 11) ^ _gf_mul(a[1], 13) ^ _gf_mul(a[2], 9) ^ _gf_mul(a[3], 14)


def _aes_block(key, block, encrypt):
    w, nr = _expand_key(key)
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    if encrypt:
        _add_round_key(state, w, 0)
        for rnd in range(1, nr):
            _sub_bytes(state, _SBOX)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, w, rnd)
        _sub_bytes(state, _SBOX)
        _shift_rows(state)
        _add_round_key(state, w, nr)
    else:
        _add_round_key(state, w, nr)
        for rnd in range(nr - 1, 0, -1):
            _shift_rows(state, inverse=True)
            _sub_bytes(state, _INV_SBOX)
            _add_round_key(state, w, rnd)
            _mix_columns(state, inverse=True)
        _shift_rows(state, inverse=True)
        _sub_bytes(state, _INV_SBOX)
        _add_round_key(state, w, 0)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_cbc_decrypt(key, data, iv=bytes(16)):
    if len(data) % 16:
        raise ValueError("datos AES no multiplos de 16")
    if _CRYPTO_AES is not None:
        return _CRYPTO_AES.new(key, _CRYPTO_AES.MODE_CBC, iv).decrypt(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = _aes_block(key, data[i:i + 16], encrypt=False)
        out += bytes(a ^ b for a, b in zip(blk, prev))
        prev = data[i:i + 16]
    return bytes(out)


def aes_cbc_encrypt(key, data, iv=bytes(16)):
    pad = 16 - (len(data) % 16)
    data = data + bytes([pad]) * pad
    if _CRYPTO_AES is not None:
        return _CRYPTO_AES.new(key, _CRYPTO_AES.MODE_CBC, iv).encrypt(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _aes_block(key, blk, encrypt=True)
        out += enc
        prev = enc
    return bytes(out)


def _pkcs7_unpad(data):
    if not data:
        raise ValueError("vacio")
    pad = data[-1]
    if not 1 <= pad <= 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("padding PKCS7 invalido")
    return data[:-pad]


# ---------------------------------------------------------------------------
# Empaquetado chino de 12 bits (c_00.chineseToBytes / bytesToChinese)
# ---------------------------------------------------------------------------

def chinese_to_bytes(s):
    length = (((len(s) * 12) // 8) // 16) * 16
    if length == 0 and len(s) > 0:
        length = 16
    out = bytearray(length)
    acc = 0
    nbits = 0
    j = 0
    for ch in s:
        acc = (acc << 12) | ((ord(ch) - 19968) & 0xFFF)
        nbits += 12
        while nbits >= 8 and j < length:
            out[j] = (acc >> (nbits - 8)) & 0xFF
            nbits -= 8
            j += 1
        # conservar solo los bits aun no consumidos (si no, acc crece sin
        # limite y el bucle se vuelve cuadratico en textos largos)
        if nbits:
            acc &= (1 << nbits) - 1
        else:
            acc = 0
    return bytes(out)


def bytes_to_chinese(data):
    acc = 0
    nbits = 0
    chars = []
    for b in data:
        acc = (acc << 8) | b
        nbits += 8
        while nbits >= 12:
            chars.append(chr(19968 + ((acc >> (nbits - 12)) & 0xFFF)))
            nbits -= 12
        if nbits:
            acc &= (1 << nbits) - 1
        else:
            acc = 0
    if nbits:
        chars.append(chr(19968 + ((acc << (12 - nbits)) & 0xFFF)))
    return "".join(chars)


def util_decrypt(text, key_text):
    """Una capa: chino -> AES/CBC(SHA-256(clave), IV cero) -> unpad."""
    raw = chinese_to_bytes(text)
    key = hashlib.sha256(key_text.encode()).digest()
    return _pkcs7_unpad(aes_cbc_decrypt(key, raw))


def util_encrypt(data, key_text):
    """Inversa de util_decrypt (para construir muestras sinteticas)."""
    key = hashlib.sha256(key_text.encode()).digest()
    ct = aes_cbc_encrypt(key, data)
    return bytes_to_chinese(ct)


def sab_decrypt(text, key_text):
    """Descifra un blob sabconfig.hs / rhtunnel.json: doble util.decrypt."""
    step1 = util_decrypt(text, key_text)
    step2 = util_decrypt(step1.decode("utf-8"), key_text)
    return step2


def sab_encrypt(data, key_text):
    """Inversa de sab_decrypt (para muestras sinteticas)."""
    inner = util_encrypt(data, key_text)
    return util_encrypt(inner.encode("utf-8"), key_text)


# ---------------------------------------------------------------------------
# XXTEA (delta no estandar de la app) + Base64 estandar (TeaBase64)
# ---------------------------------------------------------------------------

def _mx(total, y, z, p, e, k):
    return (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))


def _to_int_array(data, include_length):
    n = (len(data) + 3) // 4
    out = [0] * n
    for i, b in enumerate(data):
        out[i >> 2] |= b << ((i & 3) * 8)
    if include_length:
        out.append(len(data))
    return out


def _to_byte_array(data, include_length):
    n = len(data) * 4
    if include_length:
        m = data[-1]
        if m < n - 7 or m > n - 4:
            return None
        n = m
    out = bytearray()
    for v in data:
        out += struct.pack("<I", v & 0xFFFFFFFF)
    return bytes(out[:n])


def _fix_key(key):
    k = key[:16]
    return k + bytes(16 - len(k))


def xxtea_decrypt(data, key_text=None):
    if key_text is None:
        raise ValueError("xxtea_decrypt requiere key_text explicita")
    key = _to_int_array(_fix_key(key_text.encode()), False)
    v = _to_int_array(data, False)
    n = len(v)
    if n < 2:
        return None
    rounds = 6 + 52 // n
    total = (rounds * _XXTEA_DELTA) & 0xFFFFFFFF
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(total, y, z, p, e, key)) & 0xFFFFFFFF
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(total, y, z, 0, e, key)) & 0xFFFFFFFF
        y = v[0]
        total = (total - _XXTEA_DELTA) & 0xFFFFFFFF
    return _to_byte_array(v, True)


def xxtea_encrypt(data, key_text=None):
    if key_text is None:
        raise ValueError("xxtea_encrypt requiere key_text explicita")
    key = _to_int_array(_fix_key(key_text.encode()), False)
    v = _to_int_array(data, True)
    n = len(v)
    rounds = 6 + 52 // n
    total = 0
    y = v[n - 1]
    for _ in range(rounds):
        total = (total + _XXTEA_DELTA) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n - 1):
            z = v[p + 1]
            v[p] = (v[p] + _mx(total, z, y, p, e, key)) & 0xFFFFFFFF
            y = v[p]
        z = v[0]
        v[n - 1] = (v[n - 1] + _mx(total, z, y, n - 1, e, key)) & 0xFFFFFFFF
        y = v[n - 1]
    return _to_byte_array(v, False)


def c01_decrypt(s, key_text=None):
    """c_01.decrypt: XXTEA-Base64 -> texto."""
    if not s:
        return ""
    pt = xxtea_decrypt(base64.b64decode(s), key_text)
    return pt.decode("utf-8") if pt is not None else None


def c01_encrypt(s, key_text=None):
    """c_01.encrypt: texto -> XXTEA-Base64 (enlaces SabDev:// y shanS://)."""
    return base64.b64encode(xxtea_encrypt(s.encode("utf-8"), key_text)).decode()


def maybe_xxtea(value, key_text=None):
    """Descifra un campo del catalogo si es XXTEA-Base64; si no, lo deja igual.
    Repite hasta 3 rondas: algunos campos (p. ej. V2rayID) van cifrados dos
    veces con XXTEA, y el resultado de la primera ronda sigue siendo un
    sobre Base64. Cada ronda solo se aplica si el descifrado pasa la
    comprobacion de longitud de XXTEA y produce UTF-8 valido; un texto en
    claro que parezca Base64 no se toca porque su 'descifrado' no pasa
    esas comprobaciones."""
    if not isinstance(value, str) or not value:
        return value
    cur = value
    for _ in range(3):
        try:
            raw = base64.b64decode(cur, validate=True)
        except Exception:
            return cur
        if len(raw) < 8 or len(raw) % 4 != 0:
            return cur
        pt = xxtea_decrypt(raw, key_text)
        if pt is None:
            return cur
        try:
            nxt = pt.decode("utf-8")
        except Exception:
            return cur
        if nxt == cur:
            return cur
        cur = nxt
    return cur


# ---------------------------------------------------------------------------
# Catalogo
# ---------------------------------------------------------------------------

