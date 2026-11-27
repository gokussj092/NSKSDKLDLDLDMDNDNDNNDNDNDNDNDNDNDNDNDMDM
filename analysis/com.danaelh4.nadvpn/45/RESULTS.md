# RESULTS — NadiaVPN 1.4.6 (`com.danaelh4.nadvpn`, code 45)

## Status matrix

| Target | Status | Evidence |
|---|---|---|
| `nad://sec2:` text | **VERIFIED_REAL** | Real sample opens: HMAC verifies, JSON complete (24 keys, `nadiaSig` = `NADIA_SEC_OK`) |
| `nad://pw2:` text | **VERIFIED_SYNTHETIC** | Implemented from the DEX (25000 iter, `info` + password); round-trip with re-encrypted envelope; no real sample with a password |
| `nad://` plain text | **VERIFIED_SYNTHETIC** | JSON in clear; round-trip verified |
| `.nad` files V2 / PW2 / binary | **VERIFIED_SYNTHETIC** | Round-trip 3/3 with fresh salt+IV (prefixed V2, prefixed PW2 + password, raw binary envelope) |
| `.nad` files HWID / HWID_PW | **PENDING** | Prefixes detected; `HWID_REQUIRED` / `HWID_PASSWORD_REQUIRED` via the standard flow; with HWID supplied the decoder answers `UNSUPPORTED_VARIANT` (NHW1 slot derivation unverified, no real sample) |
| Legacy V1 (`nad://sec:` / `nad://pw:`, `NADIA_SEC_V1:`) | **PENDING** | Not analyzed; decoder answers `UNSUPPORTED_VERSION` |
| `.sks` files | **NONE** | Same intent-filter as `.nad`, but the parse path was not located in the DEX; no decoder |
| Live catalog | **NOT_APPLICABLE (excluded)** | Exists (1 free server, 0 networks, 0 payloads) but excluded from this integration by the owner's decision (2026-11-26); no catalog data, URL, host, credentials, session or token anywhere in the staging |
| SSH login (profile or catalog) | **PENDING** | Only the profile was decrypted; no login attempted |

## Tests run (2026-11-26/27, venv `~/workspace/http-custom-update/venv/bin/python`, Python 3.12.3, pycryptodome 4.4.0)

All runs in a verification overlay (`~/workspace/repo-integration/verify-nadia/`,
worktree + this staging + the 3 C8 app files missing from the local worktree,
fetched read-only from remote head `9df98013` for verification only).

- `file_decoder.py --self-test`: **OK** (V2/PW2/binary round-trips,
  tampered/V1/HWID negatives, sec2 link). Note: the self-test caught a
  real bug first (a raw binary envelope is usually not valid UTF-8, so
  the text branch threw before the binary branch); fixed in `decode()`
  and re-verified.
- `pytest tests/test_nadia_vpn.py`: **9 passed, 1 skipped** (default);
  **9 passed** with `NADIA_REAL_SAMPLE` (real sample opens, shape-only
  assertions, link never stored).
- `pytest tests/test_cloud_c8_vpn_registry.py tests/test_cat100_providers.py
  tests/test_nadia_vpn.py tests/test_text_extra_dispatcher.py
  tests/test_independent_batch_registry.py`: **39 passed, 1 skipped**.
- `pytest tests/test_cat100_providers.py`: **19 passed** (8 of them
  failed on the pristine worktree: the 287 count pin + the 3 missing
  C8 app files).
- `py_compile` on every new/modified Python file: **OK**.
- `scripts/cloud_formats_catalog.py --write` then plain run:
  **"Public Cloud format catalogue matches all currently registered
  file engines."** The staged `file-formats.json` entry for `nad` is
  byte-identical to what the regen produces (the remaining regen diff
  is pre-existing name/formatting drift in NetFlux, RMP, AM, TopPlug,
  XU, xveon/xvn — untouched here).
- Engine-level credential checks (via `engine.decode_file` /
  `engine.decode_text`): PW2 file without password →
  `PASSWORD_REQUIRED`; with password → success; wrong password →
  `AUTH_FAILED`; HWID file → `HWID_REQUIRED`; `nad://pw2:` without
  password → `PASSWORD_REQUIRED`; with password → success.
- Node direct checks (the `catalog()`-based node tests cannot run in
  a bare checkout — see Limits): `publicTextFormats()` = 91 entries
  with the `nad://` entry, prefixes unique; `SUPPLIED_INTEGRATIONS`
  = 87 with the `nadia-vpn` FILE_ONLY entry; `file-formats.json` =
  288 with the `nad` entry.
- Secret sweep over the whole staging dir (catalog values, session
  id, token, hosts/IPs, API host; 15 candidates): **0 coincidences**.
  Sample-profile values and the catalog script name appear nowhere
  except the explicit "NOT included" note in ANALYSIS.md.

## Pre-existing failures (not caused by this integration)

- `tests/test_supplied_integrations.py::test_inventory_has_all_owner_batches_and_loadable_offline_codecs`:
  the 87 count pin passes, but 18 per-provider subtests fail — 17
  pre-existing FILE_ONLY providers + `nadia-vpn`, all with the same
  root cause: the test loads `catalogModule`, which FILE_ONLY items
  do not have (`KeyError`, 6 providers incl. `nadia-vpn`) or loads a
  catalog module without a `decode`/`run` entry point (12 providers).
  The remote head has the same item shape, so the same 17 fail there.
  Test bug, flagged for the coordinator; not fixed here (out of scope).
- `tests/test_android_route_source_contract.py::test_android_structured_copy_credits_ghost_developer_only`:
  fails identically on the pristine worktree (Android copy credits,
  unrelated).
- Node `catalog()`-based tests (`text-format-catalog`,
  `file-formats`, `http-custom-online`, `server-vpn-catalog`, …):
  fail in a bare checkout with `INVALID_ORIGINAL_ICON` (icons are
  uploaded separately by the owner and are not in the worktree);
  identical on the pristine worktree. `supplied-integrations.test.mjs`
  additionally cannot import `better-auth` (not installed in the
  worktree's `node_modules`).

## Integration — SP-DECODE repo, branch `ci/unity-ads-online-qa`

Analyst work only (staged, NOT pushed, NOT deployed). Remote head at
integration time: `9df98013` (CATALOG_VERSION 100). Local worktree
HEAD `dc639d73` is dirty/stale and misses 3 C8 app files
(`XU_Tunnel/xutunnel_archivos.py`, `XVEON_Tunnel_Pro/file_decoder.py`
+ `xveon.py`, `TopPlugSA/topplugsa.py`); the coordinator applies the
staging on top of the remote head.

- Provider id `nadia-vpn`, appDir `NadiaVPN`, `FILE_ONLY` (no catalog,
  no provider card, no broker).
- Counts: C8 extended 287 → **288**; file-formats 287 → **288**;
  text-formats 90 → **91** (one `nad://` entry — the text-format
  validator rejects the `nad://sec2:` / `nad://pw2:` spellings, its
  path charset has no `:`; startswith dispatch still tells the three
  sub-schemes apart); supplied 86 → **87**; bot registry 239 → 240
  (the `nad` fixed block is excluded from the inventory count like
  the other fixed blocks); bot text handlers 38 → **41**.
- Staging: `~/workspace/repo-integration/staging-nadia/` (mirror of
  the repo-relative paths).

## Decisions left to the owner / coordinator

- HWID derivation (slots `NHW1`): needs a real HWID-locked `.nad`
  file + its HWID; until then the decoder fails closed with
  `UNSUPPORTED_VARIANT`.
- `nad://pw2:` in the Telegram bot: the bot has no password prompt
  for text links yet, so a pw2 link gets a clear "pending" reply
  instead of a prompt (no new flow invented).
- Registry decision 246 → 255 (`.pulse`/`.irfan`/`.katiba`/
  `.txtunnel`/`.fat`/`.xu`/`.xveon`/`.xvn`/`.tpc`, `v2rayng://`,
  `wyst://`) is untouched by this staging, as instructed.
- Whether to extend the text-format validator so `nad://sec2:` and
  `nad://pw2:` can be advertised as separate entries (today only
  `nad://` is advertised; dispatch is unaffected).
