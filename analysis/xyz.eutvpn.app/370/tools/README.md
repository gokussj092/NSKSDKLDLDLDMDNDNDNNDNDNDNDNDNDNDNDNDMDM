# tools/ — EUT VPN

- `crypto_pure.py`: pure-Python AES/XXTEA/Threefish/GCM helpers written for this dossier from public specifications (FIPS-197 etc.). Stdlib only.
- `verify.py`: synthetic round-trip verifier (no network, no secrets).

Research scripts copied from the investigation (secret-free, checked):

- No research script copied: the probe script used during the research embeds the format key constants, so it is deliberately withheld — keys live only in the operational scripts.
