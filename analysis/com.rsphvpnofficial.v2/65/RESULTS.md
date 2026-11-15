# RESULTS — FMT VPN (com.rsphvpnofficial.v2, versionCode 65)

Observed 2026-11-14/15. Environment for the dossier tests: Python 3.12.3 on this
VM (Linux x86_64), OpenSSL 3.0.13 as oracle, no network, no secrets.

## 1. Status per route

- **catalog**: VERIFIED — VERIFIED_REAL: live download 2026-11-14 (HTTP 200, 104,128 bytes), v2026.181, 15 servers, 75 networks; re-run with the delivered script gives the same result.
- **files**: VERIFIED — VERIFIED_SYNTHETIC: format taken from ExportActivity.java, FileUtilKt.java and UtilsKey.java; samples/sample.dtk was sealed from the live catalog (server 01 + network ALL MV FREE IMO) and reopens with the script. No real .dtk exported by the app yet.
- **text**: PENDING — PENDING: the app defines no own URI scheme; nothing to verify.
- **export**: PENDING — PENDING: no real .dtk exported by the app to compare byte for byte. COLLISION (do not resolve here): the .dtk suffix is already registered for ANY VPN build 40; the discriminator decision is pending in the discriminator phase.

Labels used here: VERIFIED_REAL = verified with a real live download or a
real app asset; VERIFIED_SYNTHETIC = verified with a synthetic vector or a
file sealed by the research script (proves the logic, not real-app
compatibility); REQUIRES_DEVICE = needs a real device; NOT_AUTHORIZED =
blocked by an authorization the research does not have (Play Integrity /
account); NETWORK_UNAVAILABLE = not attempted for lack of network.

## 2. Live evidence (from the source TESTING.md, 2026-11-14)

- Catalog: live v2026.181, 15 servers, 75 networks. Server types: 0 OpenVPN (5), 1 SSH (1), 2 (1), 3 VLESS (5), 4 UDP (1), 5 (1), 7 WireGuard (1). Networks: TunnelType 3 (51), 2 (10), 5 (7), 8 (2), 6 (2), 0 (2), 11 (1); payload_type ovpn 74, ssh 1; Payload present in 19/75, SNI in 68/75. Bundled fallback catalog (Tk.getConfig() native blob): v1.0, 1 server, 1 network. Kill-switch list consulted by the app (159 entries, 2026-11-14): FMT VPN is NOT on the list.
- Operational self-tests: catalog script --self-test 12/12 OK (AES vector verified with PyCryptodome, test blob, CJK substitution on known cases, derived key; + 4 checks added 2026-11-15: all server fields open, the empty marker encrypts '' and decrypts '', cleaning drops APIs and *_raw, U+65E5 passes through and is flagged); files script --self-test 5/5 OK (included vector opens; seal and reopen; the legacy key does not open the vector)
- Timing: Download ~0.9 s, catalog decrypt ~6.3 s (pure-Python AES), total ~9 s — under the 20 s cloud-worker limit.

## 3. Dossier tests (this dossier, offline, synthetic)

- `python3 -m unittest tests.test_method -v`: OK — Ran 6 tests in 0.098s
- `python3 tools/verify.py`: exit 0
```
PASS CJK substitution: obfuscated host decodes
PASS CJK substitution: unmapped char passes through (U+65E5)
PASS .dtk round-trip (Base64 + AES-256-CBC, {server, network})
PASS negative: short .dtk rejected
PASS negative: corrupted .dtk rejected
VERIFY OK
```

## 4. Fixture hashes (synthetic fixtures only)

- `catalog_synthetic.json`: SHA-256 `84574c21528d4da39a9b5a2d265e7b549968c0f7ace5bc26269de9f7b33ce0e1`
- `dtk_synthetic.json`: SHA-256 `b8d9ad479c167d784e2a91bee3abc6dca7ef02bf55302014115a48cccd6b1e8a`

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

- Real .dtk file exported by the app (for byte-for-byte comparison; the sample was built from live-catalog entries following the exact import code).
- U+65E5 (5 occurrences) still has no fixed value; it is passed through and flagged.
- COLLISION: .dtk is already registered for ANY VPN build 40 — the discriminator decision is pending in the discriminator phase; this dossier does NOT resolve it.
- Re-verify when the server serves a new catalog version (today 2026.181) or the app is updated (today 65).
- Full SHA-256 of the XAPK file was recorded only partially (38ead7c6...) in TESTING.md.
- NOTE ON IDENTITY: the dossier folder follows the real Android applicationId com.rsphvpnofficial.v2 (base APK com.rsphvpnofficial.v2.apk, versionName 65-16kb-page-size, versionCode 65). com.tknetwork.tunnel is the RENZ family namespace used inside the app (fork of v2rayNG, 'TK Network Tunnel'), not the applicationId.

## Revisión de conexión VPS — 2026-11-15

En `patch/20-apps` se corrigió el envío del token al servicio `web` por Docker Compose y el esquema `Authorization: Bearer <token>` del broker. El operador guarda el token sin prefijo en el entorno protegido del VPS. Prueba del broker con credenciales ficticias y red simulada: encabezado correcto hacia la fuente fija, rechazo sin red para token ausente/vacío/inyección y sin exposición en el catálogo público. No se aportó un token real en esta sesión; no se repitió la descarga remota y el estado de la evidencia histórica anterior no cambia. No se modificó el script original ni la compatibilidad del método. Véase `docs/cloud/PATCH_20_APPS_ICONS_AND_DEPLOY_2026_11_15.md`.
