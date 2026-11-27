# DEPENDENCIES — NadiaVPN 1.4.6

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12 | Runtime | PSF |
| pycryptodome | 4.4.0 (venv) | AES-256-CBC in `file_decoder.py` | BSD |
| cryptography | (fallback) | AES-256-CBC if pycryptodome is absent | Apache-2.0/BSD |

`hashlib.pbkdf2_hmac` / `hmac` / `hashlib.sha256` are stdlib. No
network, no Argon2, no extra packages. The decoder runs offline in
the existing worker subprocess (`supplied_bridge.py`) and in the
Telegram bot registry (`spdecode/registry.py`).

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| androguard 4.1.4 | DEX parsing during the original analysis |
| Unicorn | Byte-exact verification of the native mixes (0x9048, 0x8e0c, XOR-mangle) |

## What the integration does NOT depend on

- No catalog endpoint, no live API, no session/token.
- No APK at runtime; no user credentials in the repo.
- No new npm / pip dependency.
