# tools/ — Ac Tunnel VPN

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `renzutils.py`: Androguard dump of the RenzUtils class bytecode + callers of RenzUtils.decrypt/encrypt/initializeApp. Hardcoded research paths; needs androguard 4.1.4. (copied from `~/workspace/catalogs/actunnel/work/renzutils.py`)
