# DEPENDENCIES — ASL TUNNEL 3.0

Inventories what was actually used during the 2026-11-27 analysis.
Versions are the ones really used; `UNKNOWN` means the analyst did
not record it (NEEDS_REVIEW, do not invent).

## Runtime / libraries

| ID | Name | Version | Ecosystem | Purpose | License | Needs network |
|---|---|---|---|---|---|---|
| dep-python-3.12 | Python | 3.12 | python.org | Runs the decoders and tests | PSF | No (decoders); yes (live fetch) |
| dep-pycryptodome | pycryptodome (`Crypto`) | 4.4.0 | PyPI | AES/CFB, AES/CBC (catalog fields, tweaks, `.asl`) | BSD | No |

## Tools (third-party, used during the original analysis)

| ID | Name | Version | Ecosystem | Purpose | License |
|---|---|---|---|---|---|
| dep-androguard | androguard | UNKNOWN (NEEDS_REVIEW) | PyPI | DEX parsing/disassembly (`agdis.py`, `dexdis.py`) | Apache-2.0 |
| dep-capstone | capstone | UNKNOWN (NEEDS_REVIEW) | pypi.org/project/capstone | Native disassembly of `libwg-pro.so` (NoobCrypt) | BSD |
| dep-jadx | jadx | UNKNOWN (NEEDS_REVIEW) | github.com/skylot/jadx | Partial DEX decompilation (OOM; 31 MB, no ASLTunnelMain/ServerConfig) | Apache-2.0 |

## Own scripts (in `tools/`)

| Script | Purpose |
|---|---|
| `asltunnel.py` | Catalog decoder + `.asl`/`.ovpn` decoders |
| `xxtea.py` | XXTEA envelope codec |
| `fieldcrypt.py` | AES/CFB server/top-level field codec |
| `tweakcrypt.py` | AES/CBC tweak field codec |

Other analyst scripts (`dexdis.py`, `deob.py`, `decrypt_catalog.py`,
`nbdecrypt_annotated.asm`, `nbencrypt.asm`, `plt_map.json`) were used
during the analysis but are not staged here; they live in the batch
work dir (`~/workspace/batch15-work/asl-tunnel/`).

## Lockfile

No `requirements.txt`/`dependencies.lock.json` is staged: the only
runtime library is pycryptodome 4.4.0 (see MANIFEST `dependencies`).
If a lockfile is required by CI, generate it from the venv that ran
the verification (`~/workspace/http-custom-update/venv`,
pycryptodome 4.4.0, Python 3.12) — do not invent hashes.
