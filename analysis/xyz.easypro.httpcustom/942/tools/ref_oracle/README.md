# Python reference oracle (read-only copies, provenance recorded)

These three files are the oracle the C++ port was verified against. They are
copies, not new code; the C++ port must match `codec.decrypt()` output.

- `codec.py` — copy of `~/workspace/offline-hc942/staging/codec_n19.py`
  (cloud `decoders/Python/apps/HTTP_Custom/codec.py`, commit 807c71d6,
  branch ci/unity-ads-online-qa): `_derive_n19()`, b=14/e=n19 dispatch,
  `_skey` with `hc-config-part-v12`, `app_version` "8.1.5 (942)",
  `V4_PROTECTION_KEY_MAP` + `BANNER_KEY_MAP` (n19 only).
- `crypto.py` — copy of `~/workspace/offline-hc942/staging/crypto_n19.py`
  (cloud `decoders/Python/apps/HTTP_Custom/crypto.py`, same commit):
  `N19_INNER/OUTER_STATE`, `native_fold_n19()`.
- `_hc_hccfg.py` — fetched from branch ci/unity-ads-online-qa via the PAT
  helper (`/tmp/fetch_remote.py`), same commit: historical helpers
  (`_hkdf`, `_xdec`, `_pw_kdf`, `_outer_key` via `codec.OUTER_KEY`,
  `_dec_section`, `_dec_sidecar`, `_sec_list`, `_norm_prot`).

No real sample bytes, credentials, or decrypted user content are stored
here. The oracle is used only to (a) decrypt owner-supplied real files at
runtime from their private paths, and (b) build synthetic fixtures.
