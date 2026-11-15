# tools/ — ZIVPN Tunnel

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `strings.py`: Androguard dump of manifest intent-filters and DEX strings matching URL/host/scheme patterns. Needs androguard 4.1.4, lxml, loguru. Hardcoded research paths. (copied from `~/workspace/catalogs/zivpn/work/strings.py`)
