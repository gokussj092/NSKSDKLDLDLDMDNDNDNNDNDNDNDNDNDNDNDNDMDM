# DEPENDENCIES — Sentinel Tunnel 4.0.0 (`online.zarray.sentineltunnel`, vc 64)

Inventory of every tool, library and runtime really used for this
dossier and the staged decoders. Versions marked UNKNOWN were not
recorded by the analyst; they are marked, not invented.

## Runtimes and libraries (staged code)

| Name | Purpose | Version used | Ecosystem | Origin | License | Needs network? |
| --- | --- | --- | --- | --- | --- | --- |
| Python | Runtime for both staged decoders, tools and tests | 3.12 (system `python3.12`) | system | python.org | PSF-2.0 | No (decoders are offline; only the verification fetch uses it) |
| `cryptography` (PyCA) | AES-256-GCM + PBKDF2-HmacSHA256 in `file_decoder.py` | 50.0.2 in the verification venv (`/tmp/sent-venv`, 2026-11-27); the repo pins its own version | PyPI | pypi.org/project/cryptography | Apache-2.0 / BSD | No |
| Python standard library | CSV/Base64/JSON/regex/argparse/urllib in `server_catalog_decoder.py` and tools | 3.12 stdlib | system | python.org | PSF-2.0 | Only `tools/vpngate_fetch.py` (live-feed verification) |

`server_catalog_decoder.py` is stdlib-only. `file_decoder.py` needs only
`cryptography`, already a dependency of the `.st` method (the repo C0
decoder uses PyCryptodome for the same primitives; no new dependency
class is introduced).

## Investigation tools (analyst, batch work dir)

| Name | Purpose | Version | Origin | License | Notes |
| --- | --- | --- | --- | --- | --- |
| JADX | DEX decompilation of `base.apk` | UNKNOWN (not recorded) | github.com/skylot/jadx | Apache-2.0 | 78 errors; W3/* classes and data models usable |
| Unicorn engine | AArch64 emulation of `libvpscrypto.so` (HMAC + AES-GCM oracle, `emu_vpscrypto.py`) | UNKNOWN (not recorded) | unicorn-engine.org | GPL-2.0 | Oracle only; the catalog decoder is pure Python |
| apktool / androguard | APK inspection (analyst work dir) | UNKNOWN (not recorded) | apktool / androguard | Apache-2.0 / Apache-2.0 | Supporting inspection only |

## Own scripts (in this dossier / stage)

| Script | Role | Secrets? |
| --- | --- | --- |
| `decoders/Python/apps/Sentinel_Tunnel/file_decoder.py` | Canonical `.st` decoder (C8 override target) | Only the `.st` format key (legitimate decoding key, lives only here) |
| `decoders/Python/apps/Sentinel_Tunnel/server_catalog_decoder.py` | Canonical VPNGate catalog decoder (`run(bytes)->str`) | None (public feed, no auth) |
| `analysis/.../64/tools/sentinel_tunnel.py` | Analyst `.st` + link decoder, verbatim copy (SHA-256 `c73bd5949da33487848541666c21825f4b211b2532a86b2aa6284b561783ebaa`); canonical copy is `file_decoder.py` | Only the `.st` format key |
| `analysis/.../64/tools/vpngate_fetch.py` | Live-feed verification (HTTPS only) | None |
| `analysis/.../64/tests/test_sentinel_tunnel.py` | Deterministic tests, synthetic fixtures only | None |

## Deliberately NOT included

- `sentinel_tunnel_catalog.py` (analyst) is NOT copied into this
  dossier: it contains the VPS API key, HMAC key and AES key. It stays
  in the batch work dir (`~/workspace/batch15-work/sentinel-tunnel/`,
  not Git). The VPS probe is documented in REPRODUCE.md §4 with
  placeholders only.
- No APK bytes, complete catalogs, real credentials or tokens are stored
  in this dossier.

## Lockfile

No `dependencies.lock.json` is shipped: the only third-party runtime
dependency is `cryptography`, whose version is pinned by the repo, not
by this dossier. The verification venv used 50.0.2 (recorded above);
no other versions are claimed.
