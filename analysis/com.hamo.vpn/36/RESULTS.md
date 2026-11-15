# RESULTS — MNR TUNNEL PLUS (com.hamo.vpn, versionCode 36)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14 (HTTP 200, 2,155,594 B), v16.6, 30 servers, 98 networks, 0 field errors.
- **files**: VERIFIED — VERIFIED_SYNTHETIC: ejemplo.stp / ejemplo_nube.stp are synthetic (real envelope, values from a real catalog server). No real exported .stp yet.
- **text**: VERIFIED — VERIFIED_SYNTHETIC: mnrtunneludp:// code format verified by construction; no real cloud code has been downloaded from Firebase.
- **export**: PENDING — PENDING: real .stp exported by the app and a real cloud code (payload-share download) are still missing; cloud-worker time limit exceeded (see timing).

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live v16.6, 30 servers, 98 networks; bundled asset v13.9, 13 servers, 94 networks; 14 servers carry vless:// links; version check endpoint returns clear JSON (versionCode 35, versionName 3.5)
- Operational self-tests: catalog script --self-test OK (real field vector, envelope round-trip, field round-trip, FIPS-197 AES-256 vector); files script --self-test OK (.stp envelope round-trip, clear JSON, encrypted field, separate passwords)
- Timing: Pure-Python AES: decrypting the live catalog takes ~23 s locally (~1 min with download + double validation). That EXCEEDS the 20 s cloud-worker limit when run as-is — the method needs a fast AES path (e.g. argon2-cffi/PyCryptodome in the worker) or a higher worker cap before cloud use. Recorded here as a LIMIT, not as a pass.

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.047s
- `python3 tools/verify.py`: exit 0
```
PASS carrier round-trip (16-char carrier -> Base64)
PASS envelope round-trip (carrier + AES-256-CBC, key=SHA-256(hex-upper))
PASS negative: corrupted carrier rejected
PASS negative: bad PKCS#7 padding rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `catalog_synthetic.json`: SHA-256 `8afd55618a78212bd98ba1b76bc88ee7b737a51484c49585f2671944d230a9c1`
- `profile_synthetic.json`: SHA-256 `8848ca6d537a40300872a5470e7a1c062696b4cd938de9655d98b17eebdfad7d`

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

- Real .stp file exported by the app (samples are synthetic).
- Real cloud code (mnrtunneludp://...): the .sky download from Firebase has not been tested; the content decryption is the same as .stp and verified by construction.
- Cloud-worker time limit: full decrypt ~23 s locally exceeds the 20 s cap; needs a fast crypto path or a higher cap.
- The app's own E2EE tunnel protocol (ECDH P-256 + HKDF + AES-256-GCM) is out of scope for this dossier (catalog/file method only).
