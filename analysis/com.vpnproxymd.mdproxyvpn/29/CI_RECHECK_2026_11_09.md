# CI recheck — 2026-11-09

The PR against main covers earlier MD PROXY commits84496f84 and1553ce18 as well as the Thailand/KHAM additions. P06 correctly reported two previous source edits without an updated linked dossier: cloud/workers/python/server.py and decoders/Python/apps/Ultra_Tunnel/codec.py. They are now explicitly linked here; neither production source is modified by this recheck.

Observed earlier changes: heavy catalog capacity increased from1 to2 with a bounded6-second acquisition wait (four total job slots retained); MD PROXY requests two bounded independent Argon2id field workers; the shared Ultra codec normalizes actual CR/LF before indexing encrypted field keys. Original crypto parameters, whole-document output and failure behavior remain the existing contracts. The original analysis, real remote/embedded proofs, tools and fixtures remain retained.

C1's synthetic capacity-denial test still assumed that holding one heavy slot exhausted the pool. With two slots, it entered execution using an intentionally incomplete handler fixture and raised AttributeError(headers). The test now simulates a denied heavy acquisition directly and checks that normal capacity is released. No worker limits, authorization or runtime code are changed to satisfy the test.

Reproduction from repository root:

```bash
PYTHONPATH=cloud/workers/python python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
python -m unittest tests.test_md_proxy_vpn tests.test_ultra_tunnel -v
```

19 worker tests passed locally with the installed cryptographic dependencies. The dependency-free C1 runner intentionally skips crypto-only cases. MD/Ultra and the whole-PR P06 impact gate are rechecked separately; this documentation does not claim a fresh live MD PROXY download or change the existing proof's provenance.
