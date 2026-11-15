# tools/ — FMT VPN

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `xrefs.py`: Small androguard cross-reference helper used during the research. Needs androguard 4.1.4. Hardcoded research paths. (copied from `~/workspace/catalogs/fmt/work/xrefs.py`)
