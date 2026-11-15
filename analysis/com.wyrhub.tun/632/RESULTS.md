# RESULTS — HTTP Tweak (com.wyrhub.tun, versionCode 632)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14, 5 servers, all online; raw sample saved in samples/public_servers.json.
- **files**: VERIFIED — VERIFIED_REAL (asset): the real asset config.ht from the APK decrypts and re-encrypts byte-identically; the remote config.ht from GitHub also decrypts. A user-exported .ht is still pending, so the export path is VERIFIED_SYNTHETIC (muestra.ht generated with the encryptor, round-trip OK).
- **text**: PENDING — PENDING: the httptweak:// prefix is confirmed but the payload format is unconfirmed (no intent-filter, no real link).
- **export**: PENDING — PENDING: real user-exported .ht, real .hts (share) and .htb (auto-backup) files, a real httptweak:// link, a real mode-6 (v6) file, and a live code-share verification (needs account/device).

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live public catalog: 5/5 servers online (atl-global Global SSH 15%, atl-global-cf Global SSH 20%, vb-pl-1 Poland V2Ray Shadowsocks 34%, vb-pl-2 Poland V2Ray Shadowsocks 45%, vb-ca-1 Canada V2Ray Shadowsocks 29%). Public tweaks endpoint returns {} (empty). Primary source is the public JSON the app itself reads from its GitHub repo (github.public_servers field of the decrypted config); fallback is the rendered web page with the same list (types only). The rest of the API (/v1/config/*, /v1/device/register, /v1/device/subscription, /v1/auth/*, /v1/challenge) requires device registration / a user API key and is NOT used for the public catalog. The paid/subscription catalog is not accessible without an account.
- Operational self-tests: catalog script --self-test OK (5 servers, 5 online; types ssh, v2ray_ss; public_tweaks.json responds empty); files script --self-test OK (real config.ht decrypts to valid JSON, 11 root keys, 9 after cleaning APIs; re-encryption byte-identical to the original; round-trip OK)
- Timing: No timing issue recorded for the public catalog or .ht files.

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.004s
- `python3 tools/verify.py`: exit 0
```
PASS .ht envelope structure (mode 2, 16 B key, ct multiple of 16)
PASS zlib stream stage round-trips (post-decrypt plaintext)
PASS zlib magic 78 da present at level 9
PASS negative: mode 6 (v6) rejected, not invented
PASS negative: truncated blob rejected
PASS negative: invalid Base64 rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `catalog_synthetic.json`: SHA-256 `0b4617732da3d5ba920e53b3b1d1092d487664d55cfe8cd7815e570ee4863583`
- `config_synthetic.json`: SHA-256 `59e834a56fc5de60e3a36dce56e6b31cfa3d1f8f0f23c88e41e4a6097ad9397f`

No fixture contains a real credential, a real server with keys, or a real
user profile. All values are synthetic (TEST-NET addresses 198.51.100.0/24
and `TEST ...` names).

## 5. Independent-oracle checks

- Pure-Python AES in tools/crypto_pure.py: FIPS-197 AES-128 vector
  (key 000102...0f, plaintext 001122...ff -> 69c4e0d86a7b0430d8cdb78070b4c55a)
  and AES-256 vector (-> 8ea2b7ca516745bfeafc49904b496089); AES-CBC
  cross-checked against OpenSSL 3.0.13 in both directions; bad padding and
  a tampered GCM tag are rejected.
- XXTEA (deltas 0x9E3779B9, 0x85A92C1F, 0x7A56D3E1) and Threefish-256:
  encrypt/decrypt round-trips verified.
- The operational scripts were additionally verified against PyCryptodome
  4.4.0 during the research (see source TESTING.md); that oracle is not
  used by the dossier tests.

## 6. Pending (honest)

- Real .ht file exported by a user (to confirm mode 2 is the same format the app exports, not only the config.ht asset).
- Real .hts (share) and .htb (auto-backup) files.
- Real httptweak:// link to confirm the payload format.
- Real mode-6 (v6) file, if one exists.
- Live code-share verification (requires a registered account/device).
