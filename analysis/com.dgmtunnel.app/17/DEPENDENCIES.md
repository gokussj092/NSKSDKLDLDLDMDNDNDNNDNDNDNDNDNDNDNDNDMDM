# DEPENDENCIES — DGM Tunnel 15.11.2026

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |
| cryptography | 50.0.2 verified | AES-256-GCM (AESGCM) in `dgm_tunnel.py` (DGMTUNNEL_SHARE v2) | Apache-2.0/BSD |
| pycryptodome | 3.23.0 (worker pin, `requirements.txt`); 4.6.0 verified here | AES-256-GCM fallback when `cryptography` is unavailable | BSD |

`hashlib` (PBKDF2-HMAC-SHA256) / `base64` / `json` / `urllib` are
stdlib. No Argon2. No format keys.

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis |

## Lockfile

`dependencies.lock.json` pins the versions above (worker pins
where they exist; the verified venv versions otherwise).
