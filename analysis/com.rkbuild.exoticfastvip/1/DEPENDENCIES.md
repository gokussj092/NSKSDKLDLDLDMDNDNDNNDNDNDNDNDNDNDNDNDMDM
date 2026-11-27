# DEPENDENCIES — ExoticFast VIP "Rk1"

Inventories what was actually used during the 2026-11-27 analysis.
Versions are the ones really used; `UNKNOWN` means the analyst did
not record it (NEEDS_REVIEW, do not invent).

## Runtime / libraries

| ID | Name | Version | Ecosystem | Purpose | License | Needs network |
|---|---|---|---|---|---|---|
| dep-python-3.12 | Python | 3.12 | python.org | Runs the decoders and tests | PSF | No (decoders); yes (live fetch) |
| dep-pycryptodome | pycryptodome (`Crypto`) | 4.4.0 | PyPI | AES-256-CBC (outer layer) | BSD | No |

## Tools (third-party, used during the original analysis)

| ID | Name | Version | Ecosystem | Purpose | License |
|---|---|---|---|---|---|
| dep-jadx | jadx | 1.5.3 | github.com/skylot/jadx | DEX decompilation (4,213 classes, 6 errors) | Apache-2.0 |
| dep-androguard | androguard | UNKNOWN (NEEDS_REVIEW) | PyPI | DEX parsing / chunk extraction (`extract_chunks.py`) | Apache-2.0 |
| dep-jdk17 | JDK | 17.0.21+9 | Eclipse Temurin | Recompiling the patched deobfuscator (`Deob.java`) | GPL-2.0+CE |

## Own scripts (in `tools/`)

| Script | Purpose |
|---|---|
| `exoticfastvip.py` | Catalog decoder (live / `--file` / `--bundled`) + redaction |
| `xxtea_j0.py` | `j0`/`l0` XXTEA field codec |
| `rj_decoder.py` | Research `.rj`/`.js` decoder |
| `ovpn_decoder.py` | Plain `.ovpn` profile parser (helper) |

`deobfuscate.py` / `Deob.java` (LSPosed deobfuscator, bytecode-faithful
`RandomHelper.next()`) were used during the analysis but are not staged
here; they live in the batch work dir
(`~/workspace/batch15-work/exoticfast-vip/`).

## Lockfile

No `requirements.txt`/`dependencies.lock.json` is staged: the only
runtime library is pycryptodome 4.4.0 (see MANIFEST `dependencies`).
If a lockfile is required by CI, generate it from the venv that ran
the verification (`~/workspace/http-custom-update/venv`,
pycryptodome 4.4.0, Python 3.12) — do not invent hashes.
