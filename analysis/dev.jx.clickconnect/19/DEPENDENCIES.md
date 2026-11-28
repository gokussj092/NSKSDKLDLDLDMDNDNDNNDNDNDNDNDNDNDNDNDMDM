# DEPENDENCIES — VLX Tunnel VPN v1.11.24.2

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |
| cryptography | 50.0.2 verified | AES-256-GCM (AESGCM) | Apache-2.0/BSD |
| pycryptodome | 3.23.0 (worker pin, `requirements.txt`); 4.6.0 verified here | AES-256-GCM fallback when `cryptography` is unavailable | BSD |
| argon2-cffi | 25.1.0 verified | Argon2id fast path (t=3, m=8192 KiB) | MIT |

`hashlib` / `base64` / `json` / `urllib` are stdlib. A pure-stdlib
Argon2id fallback is included in the tools (slow: ~15–20 s per
envelope), so `argon2-cffi` is recommended but not mandatory.

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis |

## Lockfile

`dependencies.lock.json` pins the versions above (worker pins
where they exist; the verified venv versions otherwise).
