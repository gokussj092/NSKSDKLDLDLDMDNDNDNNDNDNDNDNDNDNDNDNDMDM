# tools/ — HTTP Tweak

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `deob_r64.py`: Dalvik abstract-interpretation deobfuscator for Lr64;->e XOR strings. Needs androguard 4.1.4. Hardcoded research paths. (copied from `~/workspace/catalogs/httptweak/work/deob_r64.py`)
