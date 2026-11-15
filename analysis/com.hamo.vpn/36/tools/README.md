# tools/ — MNR TUNNEL PLUS

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- `dad.py`: Generic androguard/DAD decompiler helper used to read the F5/G5 classes (takes the target class name as argv[1]). Needs androguard 4.1.4. (copied from `~/workspace/catalogs/mnr/work/dad.py`)
