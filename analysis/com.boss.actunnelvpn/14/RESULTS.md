# RESULTS — Ac Tunnel VPN (com.boss.actunnelvpn, versionCode 14)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14 (HTTP 200, 989,804 B Base64 -> 742,352 B), 100% of fields decrypted.
- **files**: VERIFIED — VERIFIED_SYNTHETIC: sample.actun was sealed here with the app's exact method from a real live profile (Networks[0]); sample.js is the live catalog blob. No real exported .actun yet.
- **text**: VERIFIED — VERIFIED_SYNTHETIC: actunnelvpn:// format verified by construction and round-trip; no real link exported by the app yet.
- **export**: PENDING — PENDING: a real .actun / .js exported by the app on a phone is still missing.

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live v22.242, 22 servers (12 with Username/Password), 1,227 networks (607 with Payload, 563 with SNIHost), 6,169 fields decrypted (only Version and Notes are clear text)
- Operational self-tests: catalog script --self-test 12 checks (FIPS-197 AES-128/256 vectors, XXTEA and Threefish-256 round-trips, real live-catalog field vectors for modes 0/1/2); files script --self-test 9 checks (actunnelvpn:// open, .js/.rj open, seal .actun + reopen, seal .js + reopen)
- Timing: Live download + full decrypt ~9.5 s — inside the 20 s cloud-worker limit.

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.354s
- `python3 tools/verify.py`: exit 0
```
PASS mode0 round-trip (AES-128-CBC + XXTEA delta 0x7A56D3E1 + minus-2)
PASS mode1 Threefish-256 round-trip (tweak [block, 0])
PASS mode2 PBKDF2-HMAC-SHA256(100k) + AES-256-CBC round-trip
PASS mode2 envelope layout [IV 16 B][ciphertext]
PASS negative: invalid Base64 rejected
PASS negative: corrupted ciphertext rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `catalog_synthetic.json`: SHA-256 `d885d0ad570729423612b70a0b714fa57fe0a76cae46603b9e3bb5d2df4db186`
- `profile_synthetic.json`: SHA-256 `105a8ed2f56c12f917658fbc08f17a771602126063db90c116ed2da3f120c6d4`

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

- Real .actun file exported by the app (the included sample was sealed here with the same method).
- Real .js/.rj file exported by the app (the sample is the live catalog blob, same format).
- Re-verify when the server serves a new catalog version (today 22.242) or the app is updated (today 1.4).
- SHA-256 of the full XAPK file was not recorded in TESTING.md; only the base-APK hash on disk is recorded here.
