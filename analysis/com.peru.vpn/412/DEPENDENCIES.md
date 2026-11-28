# DEPENDENCIES — Peru VPN 4.1.2

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |
| pycryptodome | 3.23.0 (worker pin, `requirements.txt`); 4.6.0 verified here | AES-256-CBC in `codec.py` (NoobCrypt fields) | BSD |

`hashlib` / `base64` / `json` / `re` / `urllib` are stdlib. No
network in the decoder itself (the CLI downloader does one plain
GET; the worker only decrypts). No Argon2.

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis (see `~/workspace/batch18-work/peru-vpn/jadx.log` for the exact invocation) |

## Lockfile

`dependencies.lock.json` pins the versions above (worker pins
where they exist; the verified venv versions otherwise).
