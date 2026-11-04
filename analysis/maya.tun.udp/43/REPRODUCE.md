# Reproduction — Maya reference

Run from the repository root. No APK compilation is needed.

```bash
python -m pip install cryptography
python analysis/maya.tun.udp/43/tools/probe_reference.py
python -m pytest -q tests/test_maya_text_reference.py
cd cloud/web && node --test tests/maya-reference.test.mjs tests/text-format-catalog.test.mjs
```

The first probe validates **only** ChaCha20-Poly1305 reference parsing locally. For optional real download, obtain permission from the GitHub repository owner and supply a **new** token through a root-only VPS environment variable, never a token argument, script constant, commit or CI log:

```bash
python analysis/maya.tun.udp/43/tools/probe_reference.py --download
```

If the repository is private or the file has been removed, expect GitHub HTTP 404. Do not assume a catalog exists and do not publish simulated server counts. A successful real test requires a fully decoded and validated JSON document and recorded redacted evidence.
