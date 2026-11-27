# RESULTS — Sentinel Tunnel 4.0.0 (`online.zarray.sentineltunnel`, vc 64)

Observed 2026-11-27. Status: **PARTIAL**.

## 1. `.st` files — VERIFIED_SYNTHETIC

| Check | Result |
| --- | --- |
| Round-trip, 7 config types × with/without password | 14/14, payload byte-identical |
| 1-byte tamper mid-file | Detected (HMAC/magic fail) |
| Password-protected file, no password given | `PASSWORD_REQUIRED` (exit 3, `{"workerError": "PASSWORD_REQUIRED"}`) |
| Password-protected file, wrong password | `AUTH_FAILED` |
| Password-protected file, correct password | Decodes (repo C0 decoder fails this case — see ANALYSIS.md §7) |
| Truncated / foreign bytes | `None` / `DECODE_FAILED`, no crash |
| Text links (vless/vmess/trojan/ss/raw JSON) | 5/5 parse (analyst self-test) |

Command: `file_decoder.py --selftest` → `SELFTEST: ALL OK` (re-run
2026-11-27 during this patch with the staged file, same result).
Dossier tests: `tests/test_sentinel_tunnel.py` → `ALL TESTS PASSED`
(3 tests: VPNGate fixture, VPNGate negatives, `.st` round-trip +
negatives).

**Limit:** synthetic only. No real `.st` export exists yet; a genuine
file is still wanted to confirm against the app's own export.

## 2. VPNGate catalog — VERIFIED (live)

| Check | Result |
| --- | --- |
| Live fetch 2026-11-27 (analyst) | HTTP 200, 1,320,394 bytes, **98 servers**, all 98 `.ovpn` Base64 decode |
| Live re-fetch 2026-11-27 (this patch) | **95 servers** (feed varies daily); 1 row with Ping `"-"` |
| Staged parser vs delivered 98-row feed | 98 servers, countries JP 50 / KR 32 / TH 7 / RU 3 / VN 2 / US 1 / RO 1 / PE 1 / MM 1 |
| Staged parser vs fresh 95-row feed | 95 servers, no crash on `"-"` Ping (analyst parser crashed here) |
| Result JSON contains download APIs? | No (asserted in dossier tests: no `vpngate.net`, no `api/iphone`, no `http://`/`https://`) |
| Protocol split (delivered sample) | TCP 80, UDP 18 (from `proto`/`remote` inside each `.ovpn`) |

## 3. Own VPS catalog — FAILED / BLOCKED (evidence, not a gap in the decoder)

| Check | Result |
| --- | --- |
| 9 types × signed request, no App Check token | HTTP 401 `{"error":"unauthorized"}` (analyst, 9/9) |
| Same, re-run 2026-11-27 (this patch) | 8× HTTP 401 + 1 connection reset (known egress flakiness) |
| Fake token / empty token / forged JWT | HTTP 401 |
| `/api/v1/configs/version` | Connection reset |
| `/api/v2/version` | 404 `{"error":"not_found"}` |
| VPS catalog version / servers delivered | Unknown / 0 — nothing invented |

## 4. Texts — VERIFIED (in code)

No own scheme. `vless://`, `vmess://`, `trojan://`, `ss://` + raw
Xray JSON parse per the app's importer (`W3/h.b`/`W3/h.d`); all already
registered generically in SP-DECODE. No new text entries.

## 5. HMAC audit — summary

- File (`.st`): CONFIRMED — HMAC-SHA256(`iv||ct`) verified before decrypt.
- VPS request signing: CONFIRMED as request signing (emulator-verified),
  NOT connection authentication.
- VPNGate feed: NOT_OBSERVED (no signature on the public CSV).
- VPN transport/connection auth: NOT_OBSERVED (VPS hy2/xray configs
  never observed; OpenVPN configs use standard certs).
- Full table: ANALYSIS.md §6.

## 6. Negative / failed attempts (kept, per evidence policy)

- VPS v2 without App Check token: 401 on all types (3 token variants).
- Analyst strict `int()` VPNGate parser on the fresh feed: crashed on
  Ping `"-"` — fixed in the staged decoder with tolerant ints.
- HTTPS to VPNGate from this VM: reset by the egress proxy; the analyst
  script falls back to plain HTTP. The staged decoder and broker use
  HTTPS only; the HTTP fallback is VM-specific and not shipped.
- No debug App Check token exists in the DEX; RTDB is permission-denied.
