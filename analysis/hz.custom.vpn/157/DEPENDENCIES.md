# DEPENDENCIES — Ultra Custom 15.7

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |
| cryptography | 50.0.2 verified | AES-256-GCM (AESGCM) and ECDSA P-256 verification in `ultra_custom.py` | Apache-2.0/BSD |
| pycryptodome | 3.23.0 (worker pin, `requirements.txt`); 4.6.0 verified here | AES-256-GCM fallback when `cryptography` is unavailable | BSD |

`hashlib` (PBKDF2) / `base64` / `json` / `zlib` (raw-DEFLATE) are
stdlib. No Argon2.

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis |

## Lockfile

`dependencies.lock.json` pins the versions above (worker pins
where they exist; the verified venv versions otherwise).
