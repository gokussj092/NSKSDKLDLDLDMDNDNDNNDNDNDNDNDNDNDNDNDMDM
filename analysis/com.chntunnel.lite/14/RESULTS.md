# RESULTS — CHN TUNNEL LITE (com.chntunnel.lite, versionCode 14)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14, re-encryption reproduces the live body byte for byte, 100% of non-empty fields decrypt (0 failures).
- **files**: VERIFIED — VERIFIED_SYNTHETIC for .js/.rj/custom_payload.json (DEX evidence complete; no real exported file yet). Live catalog blob opens as .js.
- **text**: VERIFIED — VERIFIED_SYNTHETIC: sample_link.txt is a link generated here from a real live network; no real link exported by the app yet.
- **export**: PENDING — PENDING: no real .js/.rj exported by the app and no real link with PIN (NetworkPinCode never appears in the live catalog).

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live v1.49, 5 servers, 44 networks, 12 distinct payloads, 23 distinct SNI (two live downloads, byte-identical body)
- Operational self-tests: catalog script --self-test 15/15; files script --self-test 14/14
- Timing: Live catalog download + full decrypt inside the 20 s cloud-worker budget (exact seconds not recorded; no timeout issue reported).

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.023s
- `python3 tools/verify.py`: exit 0
```
PASS mode0 round-trip (AES-128-CBC + XXTEA delta 0x85A92C1F)
PASS mode1 Threefish-256 round-trip
PASS mode2 invisible-carrier round-trip
PASS negative: truncated Base64 rejected
PASS negative: corrupted ciphertext rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `catalog_synthetic.json`: SHA-256 `93bc6134d7987a506b59f0e4b91918fbeab1d66edd68555272d2d3442a929528`
- `link_synthetic.json`: SHA-256 `a9f19dc0772e61df54f387aaa5feb2804286c7df98bb75df79396cf01530874a`

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

- Real .js/.rj file exported by the app (or a real chntunnellite:// link) to confirm the file format end to end.
- Real link with PIN (isPinEnabled + NetworkPinCode): unverified whether NetworkPinCode arrives in clear or mode-0 inside the link JSON; the script accepts both.
- Exact Expiry format: no network with expiry exists in the live catalog; the script accepts ISO date, unix seconds and unix milliseconds and reports UNVERIFIED otherwise.
- Re-verify when the catalog version rises above 1.49 or the app changes seed/salt in libovpn3.so.
