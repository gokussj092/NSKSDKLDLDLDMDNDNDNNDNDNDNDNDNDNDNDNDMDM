# RESULTS — ASL TUNNEL 3.0 (`com.asltunnel.vpn`, vc 3)

Date: 2026-11-27. Environment: Python 3.12, pycryptodome 4.4.0.

## Live catalog — VERIFIED_REAL

- Fetch: plain GET, no headers, no auth. HTTP 200, 462,840 bytes.
  Fetched twice, identical content.
- Re-fetch 2026-11-27: byte-identical to the delivered sample.
- Version 20.10; 35 servers (all free, NoobLevel 0); 292 tweaks
  (124 with Payload). Protocols: OVPN 8, SSH 8, DNS 5, Hysteria/UDP 4,
  V2Ray/ULTRA 10. 326 hosts in `ServerIPHost` (31 servers).
- 38 nested encrypted values decrypted, 0 failures. No encrypted or
  encoded value remains in the delivered JSON.
- Result JSON contains no download API.

## Files — VERIFIED_SYNTHETIC

- `.asl` plain shape (Q() config): round-trip synthetic
  (encode -> decode -> identical). Fixture `test_plain.asl`
  (Server "Test Server 1", ProxyPort "80", ExpireDate 2030-01-01).
- `.asl` server shape (LCl.b, AES/CFB fields): round-trip synthetic.
  Fixture `test_server.asl` (Name "My Custom Server", V2ray UUID,
  SlowDNS host). All server-shape fields decrypt.
- `.asl` with password: decode + report of `isPassON`/`MyPass`
  (password "secret123" in the synthetic test; note "password
  required"). The decoder reports; it does not enforce.
- `.asl` invalid: rejected (bad Base64, wrong marker).
- No real user-exported `.asl` or CONFIG KEY yet.

## Texts — VERIFIED_REAL (generic handling)

- `vmess://`, `vless://`, `trojan://`, `ss://`: verified in code
  (scheme table, import handler); standard v2rayNG import, already
  handled generically. No new entries.
- `asl://<20 chars>`: exists in code (cloud export) but resolution
  NOT verified — NOT implemented, NOT registered.

## Dossier tests

`tests/test_asl_tunnel.py` — 6 tests, synthetic fixtures only:

| Test | Result |
|---|---|
| `test_plain_asl_decodes` (bridge-adjacent `decode_asl_file`, Q shape) | PASS |
| `test_server_asl_decodes` (LCl.b shape, AES/CFB fields) | PASS |
| `test_password_shape_reported` (isPassON/MyPass notes) | PASS |
| `test_file_decoder_cli` (engine CLI contract, one JSON doc) | PASS |
| `test_invalid_asl_rejected` (bad Base64) | PASS |
| `test_empty_input_rejected` | PASS |

Run: `python3 -m pytest analysis/com.asltunnel.vpn/3/tests/test_asl_tunnel.py -v`
Observed at staging (2026-11-27, Python 3.12, pycryptodome 4.4.0):
6 passed (11 passed combined with the ExoticFast suite).

## Negative / failure cases observed

- Bad Base64 / wrong marker `.asl`: rejected with
  "Invalid config: does not belong to this app".
- Empty input: rejected.
- Bundled catalog v1.0.1 (1 server) is not the live catalog (35 servers).

## Limits (not failures)

- Synthetic round-trips prove the implemented logic, not compatibility
  with a real user-exported file; that confirmation is still pending.
- `asl://` resolution pending a real link sample.
- NoobCrypt modes 0/2/3 layouts unmapped (`.asl` uses mode 1 only).
