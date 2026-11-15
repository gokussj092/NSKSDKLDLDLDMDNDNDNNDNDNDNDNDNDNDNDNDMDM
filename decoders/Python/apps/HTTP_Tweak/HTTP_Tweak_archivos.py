#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP Tweak (.ht / .hts) — decodificador y cifrador de archivos de configuracion.
SP-DECODE / com.wyrhub.tun 1.8.17 (versionCode 632), arm64-v8a.

Formato .ht (modo 2, el usado por config.ht y por los archivos exportados):
  Base64 (texto) -> blob binario de N bytes:
    byte[0]  = modo (2)
    byte[1:17]  = clave de 16 bytes (va dentro del archivo; cambia por archivo)
    byte[17:]   = ciphertext, multiplo de 16 bytes (53 bloques en config.ht)
  Descifrado por bloque (16 bytes, CBC):
    - cifrado de bloque propio de WyrLib: 12 rondas (r=11..0). Cada ronda:
        t = estado XOR roundkey[r]
        u = permutacion P_r(t)
        estado = S-box S_r(u)      (S-box de 256 bytes, una por ronda)
    - encadenado CBC: texto[i] = D(cifra[i]) XOR prev,
      prev = clave del archivo para el bloque 0, cifra[i-1] despues.
    - el texto es un stream zlib (78 da ...) + padding de ceros a multiplo de 16.
    - zlib descomprime al JSON de la configuracion.
  Cifrado: el inverso exacto (rondas 0..11, S-box inversa, permutacion
  inversa, XOR roundkey), zlib.compress(nivel 9), padding de ceros.

Las tablas (round keys, S-boxes, permutaciones) son FIJAS para el modo 2:
se derivan en el nativo (WyrLib, libcore.so) solo del modo y del estado
interno en reposo; no dependen del archivo ni de la clave. Se extrajeron
del oraculo nativo (emulacion Unicorn de libcore.so) y se verificaron:
el descifrado reproduce byte a byte el JSON de config.ht y el cifrado
reproduce byte a byte el ciphertext real de config.ht.

Modo 6 (byte[4]==6, formato v6 con tag de 4 bytes y guarda nativa) existe
en el codigo pero no hay muestra real; no implementado (ver README).

Salida (regla SP-DECODE 2026-11-15): el JSON de resultado lleva solo
datos del catalogo/configuracion, sin las APIs de descarga del catalogo.
decode_text/decode_file/decrypt_blob devuelven el config crudo tal cual
(como lo cifra la app, para que el re-cifrado sea byte a byte identico);
clean_result() quita los campos de API (base, api) y es la salida por
defecto de la CLI al escribir el JSON.

Solo stdlib. Sin red. Sin claves reales en este archivo: la clave de cada
archivo se lee del propio archivo; las tablas son constantes del cifrado.
"""
import base64
import hashlib
import json
import os
import sys
import zlib

MODE = 2
BLOCK = 16

# ---------------------------------------------------------------------------
# Tablas fijas del cifrado de bloque modo 2 (derivadas del nativo, verificadas).
# Round keys: 12 x 16 bytes (out3 del nativo).
# S-boxes: 12 x 256 bytes (una por ronda).
# Permutaciones: 12 x 16 (una por ronda).
# ---------------------------------------------------------------------------
RK = [
    bytes.fromhex('e38950d9c8ca41b4026c8edafe0d8fd1'),
    bytes.fromhex('9e3711685885fd9b9f08c7ce5e829160'),
    bytes.fromhex('4ce9a33d572e7184d342774e9dbc4177'),
    bytes.fromhex('553b6b1118f9215c7343a4ab598f9c12'),
    bytes.fromhex('307e89e25fdd40144985b5dd945d3b77'),
    bytes.fromhex('df8ae249d9b2312fe68b1d144c950d88'),
    bytes.fromhex('0c9b7e57ca918b0834c6ef151000fd5e'),
    bytes.fromhex('2b2a285c1d8d5caa250f89bb3d7533a6'),
    bytes.fromhex('7e8bef948abff9d64342bb67a1482e6f'),
    bytes.fromhex('a8427e56d53b52719afb73f4445960d4'),
    bytes.fromhex('a29d8227707f50840351b23a4a298537'),
    bytes.fromhex('5bcbb3df4cfb492a55265737b4115582'),
]

SBOX = [
    bytes.fromhex('8b519e9d05121e44d2644a87f2adbeeb2995c3852bedf1b277280b0ec69a8aa9af30e0354124ff395da4d8a5d591435a1d82f62db61590dbb3d90c21fd261fddcd42cb1a97004863ac16714db093fc27949253fb37864b6550234f6fb57d6ed16b8301a2f8f40a69ce2afaa613257b024e761bb1e2c9eab48fe9403c811cdcae36e59f60f00717bc986af3d3f54922c7e33fe472f7bd797f7a7cc461cad6d0f9c12efec2523d788e599c58a10d04de2cb903c5e18d5670389b5bef74a32fba0f848ca86c0673a71119471031342088a0805f67d4da89df62e75c75093a66bf453ee6ee7e5799b808bb556dc8c0333b96146832544c18b75eeccccfd7ab46aae8'),
    bytes.fromhex('374b171c9de7a012a338018b621a3fac87f52cce192ed5c22934b659d3529faa679ae09edd0a5e9b503c706cabc5c310b35b4927bfc707cb79fb2adef1764ce68684357c98e5ea2da42fed093ebef9cf8a3605a8442620ffb222994e157d646a4732e18523a5bafed8535f140800c4ca5597b466afc0fc7591bdccb873c1eed2815125717793a9efd00d3df0f61833b94d6b6ed9ebae1372fd0ee34321b74f1b24dfec94f40c56650316dbdc8c40c8d6a13b54a6579295bb30828e0b28908004a2e81e968d785d4168e4cd7abc46d702fa316074e27b4548d1f7f36339a73adab01dad5c6df82b618f066f9c694a887ee958c97fc60fb5d4831189f2425ab11f'),
    bytes.fromhex('d03360b922b4af64f59a894596fa322174a06c0d805212d84c1469355d3bca2339201ccbdaeedc5c7109c1d2037b788b50edf8ddce27793d7fe5d58301864a8e3081e9472cc8954d7ebe58a8a7b30bdb53d477a11391d13443657dcc6af4f0aa4bff1fbd9db27a8d662e2d621abf3a389ca3b7e8b81de38c87f7ef6dc41e44c7bb73f1ae8a9b2ad9c2849ef692c9b06b1118f32bfbe46f635a4f0acf3c576e90ecd659c5addfb6ac75c340cd6751a55448d7ab9f68fc1646555f5626764ee72fd3f261280cea940f0e703e15e688990419240517a44941a90785e197ebba37a631fe7242935e0008a2de291bb5108f36fdc0bc2598e05bf93f028206c6b1e27c'),
    bytes.fromhex('919432104143485273059d3ab66c2406505170a0e27980e5c2236bcfe1ecc661a4127d26d2b53d99f13c92e3623ff59c5a7ac10c371a576555001fbd38dbb1825f070fd7a740c8318c6a90d36e08fac55976041b4e96cc818d53095e8ee96f0bc9ceb0c0af5bad47693489c3e8771df742d85cff0e46f2effc167f1c87cd308bda63fba64503c49a1136a2ab01fe35b475d414ae66bc97f9d06867b785dd9fa53919ca29e7acdcb2252798648a0aea72d9449b938302c7a8e62d7c3b4fa17e8feb49a978bbe01e6dcbf3334bdf95202e9ed6a317bfb97b153e2871605d18e484edfd864c2a2b4d2f2c4aee13d5d158f60daa2221baf07456f4b8de54b3f888be'),
    bytes.fromhex('a501d50ac1b2a846dc15ff07b370f4202226f56471ab28ea39335891188fba893543f79f3aa05524d973e5df3cf0ef57a29767f9feb90b6a29deace34830c79e792c52b4534b853fc0842aee7a6db594b01ae662927ebe0cd61da6bce403e0a49bb659f84136a9ec688a0650aa349d3ea7dbb890d8146c4fcdadbdfbc4174a56d1f18bc976696b0f9ca15ec52fcf60cae1e71cf6191f16bbaf25b123d08ce86388547c47514edaa39581770513ae04d37d27d400c8022b2e1bfdfa66d76f111e0d10655f8d984dcbe93bfc3d932d2183bf4487dd40eb5d45785a426e7bcc314938ce5ce208c6c3edd282746180869a4c75327f7212f25b0e9996c2f3b709378e'),
    bytes.fromhex('19a49b67a95068ba151cf78c36da72c7b816d0aef302440748c3b69a6bed80cdaa8b5481d15c694a77658fc64be4255fd730906c11b97b759c28e63558052d49b214ea2ff9632c0b0389934cbb5212854de3a7a1d3f0a584fdfb1de75a0a554fdc2ecf71c53f1b22b09e6a00e583c4b1c16482246d980e6029a634cb380db39d183c213923701fe87e27d2eea826bf765e74973d56865b01d5df2bc8d910caadccbc9404fedd99883ed696ceefa04506099179ff7d1ad8f6d4eceba2626f78de73e940923a0c1e3246f1613b7fa34142310fe037faac538d95e1b7c259b59fab2a13f58e7cfc47e26e57c00817f8db4e66f287b42033c98aafbd43bef4517a5d'),
    bytes.fromhex('cdcbd84c5803f9df7302726eeb13fed09da796f5a05a3c51dac4089b771e3f48c206e6f188957d7581e217d6afa8d7bd2a98e74663d9b762550cf7aca5e4f67e8441719e6c4752c15c1912c3f4a4f01d9440bfde24f316b0abeabe3d493b86ce79f28c4aa2112dbcbb36377f871c2b5b0722446185ed8dc026a9293582fc05c9186a892eb18e8fb2e5786db6c5e9ad4d424f56d5e1381a0a672725ef7acc2cf8040b92ae6866d15f28b3650fd2b5dbca9f3453ff595710a1544393150eba60ecc73efae333b99ac60d01305d76ee6b7c2fd38ba369093a741f459ccfd4fd90e8231420004b6f8a1bb8645e327bdc9731ddaab48391217099e0a68050c84efb39'),
    bytes.fromhex('2eb67e31b2ab20aac81b52e88aec625c30e9a99a1e2b19b3e2e684055808c63ff77fd3fa34c7177b2939d833022d632f55b13e1a3a0ae3871d1041e440950f00eebdf6ea23ed899d7254d9c577f37569a7fde5ceaccb9c8d4b99f0358f9bbe93e727c412c19fd1c37c7adb4574ae0ba00442ff1422b9576ef5a82a16fb8ebf92035e5aad6dc082379e133881bc51796c71bbf926d2b03696d601dd4673f818dcda688b6b3d21851c118c604cef662464a15bf45f43c2cc911fde2549b75d76d7d46a8347b4984adf6fcacd568878323bfc5944a3ba3cd506152809a60cd08680e12c979061b5fe67ebcfa5b8f17d5394c97007e04d65a4500df2afa24e4f0e48'),
    bytes.fromhex('fb66ff1abe6a994b9e86526d09c20dc62002e8a2902adcabf54a615a509c7a036f694fd3b7b8c43097873a152165aa63fe83f16ec0c12cca38cee6488c14e3fdb532b059db4c72dff33ca99beb60341bc710ec453146d25627ee1cac0c1fdee998ef820628aefc922f9a621907a17570531726d6797b5d3dda8512882d95963e7791e4c5410a4dd17d40c308f984f2710fcbf0fa297464f8bf432e3b5e00a7225feabad9b2d0bcb38ac99f7e8b948de025788ee2e567bb1e733701f768426b80d5e1553f49e7589d11c87c547fb4a62bccb6235ba0d7b133185cbd0ead6cd4131d4eafcda589448fa3243516f4b939cfa43657ed05d8f60b81044793dda85176'),
    bytes.fromhex('7db6957600ed560780df2e97d10b9e6f19778d4708f55d59c78731a28bf0e6f60c41586ac8a036638ebafc57a523a1031d54ab10af9fb4d9694630bb6839371c1ab744bd0645422a0d21d5844e329892ffa6131bfbf94a91dbbcec60e528eea7c6383f93ccf78c85d62c0ffed89a7bc45c6627e833f478acbfc011f353c2cb89d32fda4fb9ce648624b5a9ddc35f997f3b0a267c8f17fd16a429cf49b1905ec979de02153c40183d5a83eae7724c7ef2121ec1ef6dcad025719655618875aad2946e519b6735a3e173dc432deb1f6534098a04813a9d019ce96b74ae5badf8b2e0520582f1c5d46ce4d7a850204bfa0eb04d62cde214b3b8e322487abe3e2b70'),
    bytes.fromhex('93b3fff979476a7bb621a8a7168299dbf18e695caaaef256c24d572f1001bffecf98c97fdfca7864d2d62be0237c2615b7a23a0d3277f0686b0afc305e0f9dc1d7e79284749ad45b1a6edd1946973f4f598d3c173886d924451404af886622a6ec2a6cb0e19b5dcd1e4cc4d19c0e526171608bbad05fc7f358873e31b99e5ad3e455bc4ee8ebb1ed1b41ef4bd8a035ab3d1db511839f34d51c62098a0828f8c69650de8c75f50503817adcbef46d65ad53370b29b2c3ac0c80c8e254da5140cc256f94c01202187dfb33b48f0613bb2e00f7e93b42e67248767385206344faa3c5893667cecb1f9527f64970fd39e5a1b84390a4ea07bdeea9a52d2c4a7e91e3'),
    bytes.fromhex('da4f9b296d212cce09ef177c54f326155a977ad4f5560b3f0e6234b83c885184bed0f258eabda94566f1f063b7471091a20cebde822d645b3561e695f783b5746cc9ed183d44fa8c115cc44090ffbfb6995776c085dd719c0d4b98b93628f924c76ae20579314a93f61a383b0207aa008aa1a3d56ebc196887f865338f16597e437d75485dc173ae52ad3901bb14e1e8ee13d8e572dfab9a785ea79d12c61be4b2caec22e792e94d8dc5cdcb8e4c42e3d2db1d2023a6b33e695308b06f9f5f60b46baf89dca427fb1c0fd7a8a00637c82accfc55c3e0672b46fe30868149a51e9670f450baac7bb18bfd41d17f3a0a2ed3d925324e80cf77c2d62f1f9e039404'),
]

PERM = [
    [11, 9, 12, 13, 14, 0, 15, 7, 4, 6, 10, 2, 8, 5, 3, 1],
    [6, 15, 2, 13, 1, 3, 9, 8, 5, 11, 10, 14, 0, 7, 4, 12],
    [9, 4, 15, 7, 1, 5, 2, 10, 11, 0, 8, 13, 14, 12, 6, 3],
    [0, 14, 6, 7, 10, 1, 3, 2, 5, 12, 11, 9, 15, 4, 13, 8],
    [0, 2, 5, 12, 11, 7, 9, 15, 4, 8, 3, 1, 10, 14, 13, 6],
    [15, 13, 3, 8, 7, 9, 4, 14, 10, 0, 11, 12, 2, 6, 5, 1],
    [10, 14, 12, 8, 13, 9, 4, 3, 2, 15, 5, 0, 7, 6, 11, 1],
    [12, 11, 1, 10, 14, 2, 3, 4, 0, 9, 8, 13, 6, 15, 5, 7],
    [12, 15, 13, 10, 4, 8, 11, 5, 3, 14, 0, 6, 2, 7, 9, 1],
    [15, 10, 4, 6, 2, 12, 5, 0, 14, 9, 3, 1, 7, 11, 13, 8],
    [10, 13, 1, 7, 9, 14, 4, 6, 3, 8, 5, 15, 11, 2, 0, 12],
    [9, 7, 6, 11, 10, 13, 1, 3, 12, 5, 0, 14, 2, 4, 8, 15],
]

_SBOX_INV = None
_PERM_INV = None


def _inv_tables():
    global _SBOX_INV, _PERM_INV
    if _SBOX_INV is None:
        _SBOX_INV = []
        for r in range(12):
            inv = [0] * 256
            for i, v in enumerate(SBOX[r]):
                inv[v] = i
            _SBOX_INV.append(bytes(inv))
        _PERM_INV = []
        for r in range(12):
            inv = [0] * 16
            for j, i in enumerate(PERM[r]):
                inv[i] = j
            _PERM_INV.append(inv)
    return _SBOX_INV, _PERM_INV


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _block_decrypt(cblk):
    """Descifra un bloque de 16 bytes (rondas 11..0)."""
    st = cblk
    for r in range(11, -1, -1):
        t = _xor(st, RK[r])
        u = bytes(t[PERM[r][j]] for j in range(16))
        st = bytes(SBOX[r][b] for b in u)
    return st


def _block_encrypt(pblk):
    """Cifra un bloque de 16 bytes (rondas 0..11, inversas)."""
    sinv, pinv = _inv_tables()
    st = pblk
    for r in range(0, 12):
        u = bytes(sinv[r][b] for b in st)
        t = bytes(u[pinv[r][j]] for j in range(16))
        st = _xor(t, RK[r])
    return st


# ---------------------------------------------------------------------------
# Formato .ht
# ---------------------------------------------------------------------------

def parse_blob(blob):
    """Descompone el blob binario. Devuelve (modo, clave, ciphertext)."""
    if len(blob) < 1 + 16 + 16:
        raise ValueError('blob demasiado corto: %d bytes' % len(blob))
    mode = blob[0]
    if mode != MODE:
        raise ValueError('modo no soportado: %d (solo modo 2 verificado)' % mode)
    key = blob[1:17]
    ct = blob[17:]
    if len(ct) % BLOCK:
        raise ValueError('ciphertext no es multiplo de 16: %d bytes' % len(ct))
    return mode, key, ct


def decrypt_blob(blob):
    """blob binario -> dict JSON de la configuracion."""
    mode, key, ct = parse_blob(blob)
    pt = bytearray()
    prev = key
    for i in range(0, len(ct), BLOCK):
        blk = ct[i:i + BLOCK]
        f = _block_decrypt(blk)
        pt += _xor(f, prev)
        prev = blk
    # el stream zlib termina antes del padding de ceros
    d = zlib.decompressobj()
    out = d.decompress(bytes(pt))
    return json.loads(out.decode('utf-8'))


def encrypt_blob(config, key=None):
    """dict JSON (o bytes JSON) -> blob binario modo 2 listo para Base64."""
    if isinstance(config, dict):
        raw = json.dumps(config, separators=(',', ':'),
                         ensure_ascii=False).encode('utf-8')
    elif isinstance(config, (bytes, bytearray)):
        raw = bytes(config)
    else:
        raw = str(config).encode('utf-8')
    comp = zlib.compress(raw, 9)
    pad = (-len(comp)) % BLOCK
    comp += b'\x00' * pad
    if key is None:
        key = os.urandom(16)
    if len(key) != 16:
        raise ValueError('la clave debe ser de 16 bytes')
    ct = bytearray()
    prev = key
    for i in range(0, len(comp), BLOCK):
        blk = comp[i:i + BLOCK]
        x = _xor(blk, prev)
        c = _block_encrypt(x)
        ct += c
        prev = c
    return bytes([MODE]) + key + bytes(ct)


def decode_text(text):
    """Texto Base64 de un .ht -> dict JSON."""
    if isinstance(text, str):
        text = text.strip().encode('ascii')
    blob = base64.b64decode(text)
    return decrypt_blob(blob)


def encode_text(config, key=None):
    """dict JSON -> texto Base64 de un .ht."""
    return base64.b64encode(encrypt_blob(config, key)).decode('ascii')


def decode_file(path):
    with open(path, 'rb') as fh:
        data = fh.read()
    # el archivo puede ser el texto Base64 o el blob binario
    try:
        text = data.decode('ascii').strip()
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
               for c in text) and len(text) >= 4:
            return decode_text(text)
    except (UnicodeDecodeError, ValueError):
        pass
    return decrypt_blob(data)


def encode_file(config, path, key=None):
    text = encode_text(config, key)
    with open(path, 'w', encoding='ascii') as fh:
        fh.write(text)
    return path


# Campos de API de descarga del backend: no van en el JSON de resultado
# (regla SP-DECODE 2026-11-15: el resultado lleva solo los datos del
# catalogo/configuracion, todo descifrado). Se quitan 'base' (website,
# api, panel, event_images), 'api' (endpoints config/auth/analytics/
# promotions), 'source' (URL de descarga del propio config.ht) y 'github'
# (URLs raw de los catalogos remotos: public_servers, public_tweaks,
# releases, android-games, carrier-networks). El resto (link, social,
# pages, log_filter, features, toolbar_events, vpn, updated_at) son
# datos de la app y se conservan. La procedencia (source) queda
# documentada en TESTING.md/NOTES.md, no en el JSON de resultado.
API_FIELDS = ('base', 'api', 'source', 'github')


def clean_result(cfg):
    """Config crudo -> JSON de resultado limpio (sin campos de API).
    Devuelve una copia; el dict original no se modifica."""
    return {k: v for k, v in cfg.items() if k not in API_FIELDS}


# ---------------------------------------------------------------------------
# Self-test: usa el asset real config.ht (copia sanitizada en samples/) y
# verifica descifrado exacto + round-trip cifrado -> descifrado.
# ---------------------------------------------------------------------------
def _self_test():
    here = os.path.dirname(os.path.abspath(__file__))
    sample = os.path.join(here, 'samples', 'config.ht')
    if not os.path.exists(sample):
        sample = os.path.join(here, 'samples', 'config_decrypted.json')
        print('self-test: no hay config.ht de muestra; se usa config_decrypted.json')
        with open(sample, 'r', encoding='utf-8') as fh:
            cfg = clean_result(json.load(fh))
        text = encode_text(cfg, key=bytes.fromhex(
            'c0a3b568b1722d4bcd8f5399c3a689ad'))
        back = decode_text(text)
        assert clean_result(back) == cfg, 'round-trip fallo'
        print('self-test OK: round-trip cifrado/descifrado (muestra JSON)')
        return True
    with open(sample, 'r', encoding='ascii') as fh:
        text = fh.read().strip()
    cfg = decode_text(text)
    assert isinstance(cfg, dict), 'el descifrado no es un dict'
    # El config CRUDO trae base y api: se verifican aqui como prueba de
    # que el descifrado es exacto; la salida limpia los quita (ver abajo).
    assert cfg.get('base', {}).get('website') == 'https://httptweak.com', \
        'website inesperado: %r' % cfg.get('base', {}).get('website')
    assert cfg.get('link', {}).get('config_prefix') == 'httptweak://', \
        'config_prefix inesperado'
    assert cfg.get('api', {}).get('config', {}).get('fetch') == '/v1/config', \
        'endpoint fetch inesperado'
    # round-trip: cifrar el JSON descifrado con la MISMA clave del archivo
    # debe reproducir el ciphertext real byte a byte (se usa el config
    # crudo, porque es lo que cifra la app)
    blob = base64.b64decode(text)
    key = blob[1:17]
    re_enc = encrypt_blob(cfg, key=key)
    assert re_enc == blob, 'el re-cifrado no reproduce el blob real'
    # salida limpia: sin campos de API (regla SP-DECODE 2026-11-15)
    cleaned = clean_result(cfg)
    assert 'base' not in cleaned and 'api' not in cleaned \
        and 'source' not in cleaned and 'github' not in cleaned, \
        'la salida limpia aun trae campos de API: %s' % sorted(cleaned)
    assert len(cleaned) == len(cfg) - len(API_FIELDS), \
        'la limpieza quito mas de lo debido: %d -> %d' % (len(cfg), len(cleaned))
    assert cleaned.get('link', {}).get('config_prefix') == 'httptweak://', \
        'config_prefix perdido en la limpieza'
    # round-trip con clave nueva sobre la salida limpia
    text2 = encode_text(cleaned)
    assert clean_result(decode_text(text2)) == cleaned, \
        'round-trip con clave nueva fallo (salida limpia)'
    print('self-test OK: config.ht descifra a JSON valido (%d claves raiz, '
          '%d tras limpiar APIs), re-cifrado byte a byte identico al '
          'original, round-trip OK'
          % (len(cfg), len(cleaned)))
    return True


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        ok = _self_test()
        sys.exit(0 if ok else 1)
    if len(sys.argv) < 2:
        print('uso: HTTP_Tweak_archivos.py [--self-test] <archivo.ht> '
              '[salida.json]')
        print('     decodifica un .ht a JSON (o imprime el JSON).')
        print('     La salida es el JSON de resultado limpio: sin los '
              'campos de API de descarga (base, api, source, github).')
        sys.exit(2)
    cfg = clean_result(decode_file(sys.argv[1]))
    out = json.dumps(cfg, indent=2, ensure_ascii=False)
    if len(sys.argv) >= 3:
        with open(sys.argv[2], 'w', encoding='utf-8') as fh:
            fh.write(out)
        print('escrito %s' % sys.argv[2])
    else:
        print(out)
