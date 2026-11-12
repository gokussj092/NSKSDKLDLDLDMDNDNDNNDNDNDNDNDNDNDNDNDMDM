# HTTP Injector 6.5.0/build244 — HMAC usage audit

Scope: identify presence without collecting service authentication material. Package/build and SHA256 are in generated/identity.json. Only82 methods are visible in the base DEX. Native markers are present; this inventory does not cover all application logic or establish how native/protected code behaves.

Observed: 1 DEX, 82 methods visited, 0 Mac.getInstance references, 0 Mac.init references, 0 Mac.doFinal references and 15 native libraries inspected for fixed algorithm markers. These are static counts, including dependency code. No execution or protocol-role assertion follows from their presence.

The scanner retains only fixed algorithm names, counts, hashes, identity and explicit uncertainty. It does not collect class/function operands, function inputs/outputs, private keys, tokens, generated HMAC secrets or decrypted VPN profiles. No hook or vendor APK/native code executed. No connection was made to a VPN/authentication endpoint.

`connection_authentication.status` remains UNCONFIRMED. No keys were extracted; no catalog, decoder, file export or service route was activated. The audit rule is documented in AGENTS.md and section2.2 of METHOD_EVIDENCE_POLICY.md; no new automatic CI gate or F7 execution is claimed.

## Server catalog reinvestigation — 2026-11-09

Scope: identify a reproducible server-list source for this same user-supplied build. This supplements the aggregate audit; it does not change its HMAC findings. The base DEX consists of the SecNeo loader (7 classes, 82 methods), rather than the full app. `assets/info.y` is 10,382 bytes of unclassified data, not a verified server JSON. Resources/native literals exposed legal URLs only. None is catalog-download evidence.

Read-only inspection of historical branch `analysis/http-injector-650-json-audit`, pinned at `03bc9fe3c20a464dd1ea3848850b2d0227f5f477`, found documentation for this exact ZIP/base hash and an owned container-unpacking script. The script is preserved verbatim under the new intake's `tools/historical/`; its upstream path is `scripts/research/httpinjector_650_unpack_native.py`. The earlier cloud-configuration import method is a separate feature and was not used as proof of a server catalog. Service signing secrets from historical materials were not copied or reused.

Static container decoding recovered the inner ARM64 `libDexHelper` and `libdexjniehi` ELF data. The ARC4/XOR parameters used here belong to the embedded native container, not service authentication. No recovered library was loaded or executed. Applying those two documented layouts to `libevozi`, `libevozi_sentinel`, `libdf` and `libtunnelcore` failed their parameter/ELF validations; those unsuccessful attempts are recorded rather than treated as successful recovery.

The pinned `libdatajar` has a Zstandard frame at `0xe89018`, length `0x4de074`. The host libzstd 1.5.7 decompressed it to 31,457,280 bytes, SHA256 `c27c702a5b4ed762b3389777a14547650e056615999bfcb9cf8b29b5ff22e654`. This is data parsing, not APK/native execution. Exact-name/URL scans of the frame and recovered inner libraries found no catalog route. This negative result is limited to literal scans, not proof that a route does not exist.

The primary partial metadata map was located at file offset `0x163600`, base `0x4018`. Walking string-data items independently of overwritten string-ID tables recovered selected type identifiers: `ServersActivity`, its encrypted-response/old-data callbacks, `LogicalServers`, `ConfigEhiServer`, `EncryptedApi` and `HomeFragment.fetchAndUpdateServerConfig` callbacks. These names establish UI/model presence only. They do not establish an endpoint, transport cipher or access policy. Only 10,600/11,624 primary type references point within the recovered string pool; secondary references are 12,653/12,653 and tertiary 0/3,354. Treat these as incomplete metadata, not executable DEX files.

Exploratory direct type-table/class-data parsing failed with out-of-range references and invalid method/code offsets. It was not used to reconstruct request behavior. The historical private helpers `recover_secondary_dex.py`, `deobfuscate_strings.py` and `constant_fold_dex.py` are described by the old dossier but were not found in the available checkout/history or named-file search. No complete reconstruction is claimed. `adb`, an Android emulator and `/dev/kvm` were also unavailable in this workspace; no device trace was captured.

**Observed result: PENDING.** No valid server-list request or complete response was obtained. HTTP status, record count and download-authentication requirements remain unknown. No provider card, runtime adapter, cloud route, APK build or catalog activation was added. Next useful evidence is an authorized, sanitized server-list request trace/export or the missing historical reconstruction helpers. Exclude tokens, request-signing secrets and VPN account credentials from published evidence.
