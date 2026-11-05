# Reproduction (network-connected host, private XAPK)

Only Python standard library is required. From repository root:

```bash
python3 -m unittest discover -s analysis/com.tunneldoom.http/432/tests -v
umask 077
python3 analysis/com.tunneldoom.http/432/tools/acquire.py \\
  --output /var/tmp/tunneldoom-4.3.2-candidate.xapk
```

The downloader contacts the fixed publicly documented APKPure XAPK URL, does not accept a client URL, limits file size to 125 MiB, verifies ZIP and XAPK manifest metadata, and refuses overwrite. If APKPure redirects to a CDN outside the restricted allowlist it **fails closed**: review legitimate redirect host before changing the allowlist. An unexpected or older version is rejected and not saved.

On success, validate base APK version with Android SDK `aapt` / `apkanalyzer`, validate signing certificate with `apksigner`, and statically inspect `ConfigUpdateco.doInBackground` with an appropriately reviewed version of JADX. Do not execute or install the downloaded APK, and do not commit the XAPK, secrets, server catalogs or decoded payloads. Use `scripts/apk_analysis/tunneldoom_verify.py` with an independently captured encrypted catalog after obtaining a confirmed updater source.
