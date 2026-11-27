# DEPENDENCIES — ThaiVPN Connect 2.4

## Runtime (decoder)

| Dependency | Version | Use | License |
|---|---|---|---|
| Python | 3.12.3 | Runtime | PSF |

Standard library only (`base64`, `json`, `re`, `urllib` for the
analyst CLI's live fetch). No `cryptography`, no `pycryptodome`,
no Argon2, no network in the bridge/file decoders (the broker
downloads; the worker only decrypts).

## Analysis-only (not needed at runtime)

| Dependency | Use |
|---|---|
| jadx | DEX decompilation during the original analysis (see `~/workspace/batch17-work/thaivpn/jadx.log` for the exact invocation) |

## Lockfile

`dependencies.lock.json` pins Python 3.12.3 and records that the
decoder has no third-party runtime dependencies.
