# Tools actually exercised / proposed

The QA first pass calls `cloud/apk_analysis/input_gate.py` and `cloud/apk_analysis/qa_static.py` only. They parse ZIP metadata, AndroidManifest header and DEX header without installing or running APK code. The 63 scripts under `scripts/apk_analysis/` and all VPN decoders remain intact and UNREVIEWED for automatic research. Tests have been staged but not run in current CI due to runner startup failures.
