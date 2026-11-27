# DEPENDENCIES — STLRAY 1.1.36

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |
| pycryptodome | 3.23.0 (worker pin, `requirements.txt`); 4.6.0 verified here | AES-256-GCM in `stlray.py` (catalog layers + TVC layers) | BSD |
| cryptography | 50.0.2 (worker pin + verified) | ECDSA P-256 catalog signature verification | Apache-2.0/BSD |

`hashlib` / `hmac` / `gzip` / `zlib` / `json` / `base64` are
stdlib. No network in the decoders (the broker downloads; the
worker only decrypts). No Argon2.

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis (see `~/workspace/batch17-work/stlray/jadx.log` for the exact invocation) |

## Lockfile

`dependencies.lock.json` pins the versions above (worker pins
where they exist; the verified venv versions otherwise).
