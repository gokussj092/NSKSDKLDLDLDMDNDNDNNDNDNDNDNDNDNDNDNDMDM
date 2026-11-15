# RESULTS — ZIVPN Tunnel (com.zi.zivpn, versionCode 184)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14 (HTTP 200, JSON 971 B, 1 configuration), re-verified at delivery with --url (same result).
- **files**: VERIFIED — VERIFIED_SYNTHETIC: golden .ziv vector (fixed salt/iv) opens; legacy and export-style round-trips OK; ejemplo.ziv / ejemplo_export_style.ziv were sealed by the script. No real .ziv exported by the app yet.
- **text**: PENDING — PENDING: no own URI scheme exists; nothing to verify beyond the standard V2Ray links (already covered generically).
- **export**: PENDING — PENDING: a real .ziv exported by app 2.2.5 is missing (it would confirm the method and the LF1/DES asymmetry end to end).

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live: JSON of 971 B with a single key -> Base64 of 704 B -> decrypted XML of java.util.Properties: tunnelType 4 = psiphontunnel, local SSH port 1080, file.appVersionCode 24. There is no server list or HTTP payload list in this endpoint: the 'catalog' is one remote configuration the app stores as remote_<name>. Bundled Psiphon servers live in assets zifile (225 servers) and zifile2 (41 servers) — hex of concatenated JSON documents, not a downloadable catalog.
- Operational self-tests: catalog script --self-test OK (1 configuration, Global UDP, Psiphon); files script --self-test OK (DES/AES vectors, golden .ziv, round-trips, XML, zifile)
- Timing: No timing issue recorded; GCM/PBKDF2 work is small (single config / single file).

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.102s
- `python3 tools/verify.py`: exit 0
```
PASS .ziv envelope round-trip (PBKDF2-SHA256 1000 + AES-128-GCM)
PASS DES-ECB round-trip via openssl oracle
PASS negative: envelope with 2 parts rejected
PASS negative: tampered GCM tag rejected
PASS negative: wrong password rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `config_synthetic.json`: SHA-256 `2efa881688f7e6b3aef29d433fa11f601284915cf1a77806534791969ce52272`
- `properties_synthetic.xml`: SHA-256 `1505a0d22bdfd683fb91a2295ca8845b0bddd275e7ee25575b8fcb79523a0fb9`

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

- Real .ziv file exported by app 2.2.5 (confirms the method and the export/import asymmetry end to end).
- Live capture of the RestoreAccess flow (real account) and of the remote-config selection on the phone.
- Re-verify profiles.json when it changes (today 1 config, appVersionCode 24).
- Full SHA-256 of the XAPK file was recorded only partially (ae6cdb7e...) in TESTING.md.
