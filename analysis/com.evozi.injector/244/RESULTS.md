# Results

Identity and aggregate static inventory completed for HTTP Injector build244. VPN-connection HMAC authentication remains UNCONFIRMED. Only82 methods are visible in the base DEX. Native markers are present; this inventory does not cover all application logic or establish how native/protected code behaves.

Two isolated scanner boundary tests passed: a fictional secret in DEX strings/instruction operands is absent from both report and stdout; altered input bytes are rejected before creating a report. These synthetic tests validate audit redaction/identity handling, not a real service authentication protocol. Schema checks for the sanitized dossier are reproducible offline. No real authentication keys, sessions or connections were tested.

## Catalog investigation — PENDING

The complete static recipe ran against the supplied 6.5.0/build244 archive. Two native containers and the 31,457,280-byte Zstd frame were recovered as private data, with hashes in `generated/catalog-research-summary.json` and the frame report. Selected primary type names identify the server UI and models. Four additional native-container attempts failed validation; all are preserved in the native report.

No catalog request was reconstructed and no server list was downloaded. `catalogHttpStatus` and `serverRecordCount` are null; `downloadAuthentication` is UNCONFIRMED. Literal-only negative scans do not prove the absence of an API, and callback/type names do not prove encryption or authentication behavior. The prior cloud-config import result is not a catalog result. No runtime integration was enabled.

`python -m unittest discover -s analysis/com.evozi.injector/244/tests -v` passed 6 tests (the existing aggregate-report check plus 5 catalog parser/report boundaries). They verify query/userinfo/opaque-segment redaction, rejection of a wrong build before decompression, selected-type filtering, invalid ULEB128 rejection and explicit pending/null report fields. These synthetic/schema checks do not validate any live server, account or catalog. Research dependencies and exact commands are recorded in DEPENDENCIES/REPRODUCE.
