# REPRODUCE — SNI Tunnel 1.3.7

Environment: Python 3.12.3; `cryptography` (ECDH P-256, HKDF-SHA256,
ChaCha20-Poly1305, AESGCM) — the tool needs `cryptography` for the
v2rc seal; `pycryptodome` is used only as an AES-GCM fallback.
Verified with the venv at `~/workspace/.venv-mehaf/bin/python`
(cryptography 50.0.2, pycryptodome 4.6.0; the worker image pins
pycryptodome 3.23.0 — the AES-GCM calls used are the same, but the
coordinator should run the worker suite against 3.23.0). Paths
below are repo-relative; from this staging root they work
identically (the staging tree mirrors the repo layout).

## 0. App key material (not stored in this dossier)

```bash
export SNI_TUNNEL_APP_PRIV_B64=<deobfuscated app private key, base64>
export SNI_TUNNEL_APP_PUB_B64=<deobfuscated app public key, base64>
```

The values live only in the batch report
(`~/workspace/batch18-work/sni-tunnel/REPORTE.md`). For the
synthetic tests only, the tool generates a fresh test P-256
keypair — it opens no real link.

## 1. Dossier tests (synthetic fixtures only, no network)

```bash
~/workspace/.venv-mehaf/bin/python -m unittest discover \
  -s analysis/com.asnly.snitunnel/40/tests -v
# Expected: 8 passed
```

Fixtures: synthetic standard links (`synthetic_links.txt`), all
TEST-NET (`203.0.113.x`) and test UUIDs. No keys, no real
credentials, no live bytes.

## 2. v2rc link (out-of-band, never stored in the repo)

```bash
export SNI_TUNNEL_APP_PRIV_B64=... SNI_TUNNEL_APP_PUB_B64=...
~/workspace/.venv-mehaf/bin/python \
  analysis/com.asnly.snitunnel/40/tools/sni_tunnel.py \
  open <enlace v2rc>
# Expected: the outer layer opens (ECDH + HKDF + ChaCha20-Poly1305);
# the inner config needs the link password (PBKDF2, 120,000 iters).
# The real 'SOMBRE' link is expired and its password is unknown.
```

## 3. Cloud relay (live, out-of-band)

```bash
~/workspace/.venv-mehaf/bin/python \
  analysis/com.asnly.snitunnel/40/tools/sni_tunnel.py \
  cloud-create --config <config.json>
# Expected: a v2rcloud link; claim it once (a second claim
# returns 410). Verified live 2026-11-28.
```
