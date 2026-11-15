# tools/ — CHN TUNNEL LITE

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `decode_vq.py`: LSParanoid string-table extractor used during the research (androguard + loguru). Hardcoded research paths; run as-is only inside the research workspace. (copied from `~/workspace/catalogs/chn/work/decode_vq.py`)
