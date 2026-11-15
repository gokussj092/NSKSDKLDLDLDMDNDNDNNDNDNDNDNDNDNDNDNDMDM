"""Wolf build16 public native client format; no account/subscription credentials."""
from __future__ import annotations
import base64
from functools import lru_cache
from Crypto.Cipher import AES
from argon2.low_level import Type, hash_secret_raw

# Public app-wide KDF inputs recovered from build16 libgojni.so. These are not
# user passwords or API authentication tokens. Evidence exports their SHA-256.
CATALOG_SEED = bytes.fromhex("38655a4778795835302f785254732f45546d586c62566169495a52764c496b31")
FIELD_SEED = bytes.fromhex("345669344b5465566c55572b4d336973456e3258446f4345686865694a707136")
MAX_BYTES = 8*1024*1024

class AuthenticatedTextError(ValueError):
    """GCM authenticated, but plaintext is not UTF-8; never try another codec."""

@lru_cache(maxsize=2048)
def _key(seed: bytes, salt: bytes) -> bytes:
    return hash_secret_raw(seed,salt,3,8192,1,32,Type.ID,version=19)

def decrypt(value: str, *, transport: bool=False) -> str:
    if not isinstance(value,str) or len(value)>MAX_BYTES*2:
        raise ValueError("WOLF16_INVALID_CARRIER")
    text=value.replace("\r","").replace("\n","")
    if transport:
        if len(text)<5 or len(text)%4!=1 or not text[3].isascii() or not text[3].isalpha():
            raise ValueError("WOLF16_INVALID_TRANSPORT")
        text=text[:3]+text[4:]
    raw=base64.b64decode(text,validate=True)
    if len(raw)<44:raise ValueError("WOLF16_TRUNCATED")
    salt=raw[:16]
    cipher=AES.new(_key(CATALOG_SEED if transport else FIELD_SEED,salt),
                   AES.MODE_GCM,nonce=raw[16:28])
    cipher.update(salt)
    clear=cipher.decrypt_and_verify(raw[28:-16],raw[-16:])
    try:return clear.decode("utf-8")
    except UnicodeError:raise AuthenticatedTextError("WOLF16_TEXT_INVALID") from None

