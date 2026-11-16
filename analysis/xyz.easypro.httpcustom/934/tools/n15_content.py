"""Research-only HCCFG 12/n15 content-key composition, verified on six exports.

HMAC prestates were supplied in the owner's script; SHA-256 continuation is
the existing independently implemented build-899 helper. This does not enable
any production route and does not implement n16, activation or Access ID.
"""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT))
from decoders.Python.apps.HTTP_Custom.crypto import CERT_SHA256,sha256_from_state
from decoders.Python._hc_hccfg import _hkdf

INNER=(0xaabd3a1e,0x3d63a211,0xe615b378,0x46a07517,0x11f5cab4,0xa7aef829,0x83c7543b,0x2d971ab7)
OUTER=(0x423fcb79,0xc4dd3dc8,0x57d814ac,0x1660ed59,0xdbb328b7,0xcc389261,0x06f1803e,0xe3130c6b)

def derive(seed:bytes,aad:bytes,password_key:bytes=b'')->bytes:
    if not isinstance(seed,bytes) or len(seed)!=32:raise ValueError('Invalid seed')
    if not isinstance(aad,bytes) or not aad:raise ValueError('Invalid AAD')
    if not isinstance(password_key,bytes) or len(password_key) not in (0,32):raise ValueError('Invalid password-key length')
    folded=sha256_from_state(OUTER,sha256_from_state(INNER,b'\xf1'+CERT_SHA256+aad))
    return _hkdf(folded+password_key,seed,b'hc-config-content-v12')
