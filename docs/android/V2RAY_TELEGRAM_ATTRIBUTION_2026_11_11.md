# V2Ray preview, Telegram decryption attribution and share links

## Scope
Android SP-DECODE Online QA, source branch feat/nuevas-integraciones.
No server, decoder, protocol authentication or history format is modified.

## Nested JSON display
A decoded HC result may store `Config.v2rayConfig` as a JSON-encoded string.
The result viewer uses the existing `ResultJsonDisplay.render` parser to
expand it for display only (input bounded to 500,000 characters). The original
worker rawText, encrypted on-device history and ORIGINAL file export remain
unchanged. For very large results, the streaming viewer remains authoritative.

## Decryption credits
Settings > Decryption credits accepts a Telegram username, with or without
one or more leading `@` signs; persisted format has exactly one `@`.
5-32 ASCII letters, digits and underscores are accepted; blank clears it.
Stored only in private SharedPreferences on device, not on the server.
JSON and original Telegram clipboard messages include the selected-language
`Decrypted by @username` (Spanish `Descifrado por @usuario`) outside JSON
fences; ORDERED shares include only the credit line before the existing
ordered content. Powered by Ghost Developer remains once. File exports remain
pure JSON or raw text without Telegram credit text.

## V2Ray links
Copy dialog offers **Copy detected V2Ray links** and protocol-specific buttons,
only if a valid existing outbound of that protocol is available in decoded
V2Ray settings. VMess uses `vmess://` plus Base64 JSON (v2rayN format).
VLESS and Trojan use their own URI syntax only when the original outbound
declares them. The converter carries UUID/password, address/port, transport,
WebSocket host/path, gRPC name and TLS/SNI within the supported subset.
Unsupported/insufficient/REALITY variants are withheld, not guessed.
This does **not** transform the remote server from one protocol to another,
nor guarantee import by HTTP Custom/NPV Tunnel; the destination app must
understand the generated link. Plain links (without credits/Markdown) are
copied to support compatible client import. Share links can reveal credentials.

## Verification
- Source preflight: tests/test_android_unity_release_contract.py on QA branch
- Instrumented source tests: V2rayShareLinksInstrumentedTest.kt (synthetic only)
- Build/sign: .github/workflows/android-unity-ads-online-qa.yml
- Remaining device QA: nested v2rayConfig JSON expansion in a real HC file;
  Telegram handle persistence after app restart; sharing in each language;
  VMess URL import into a compatible client; negative unsupported protocols.

## Saved alias UX (2026-11-12)

The previous screen permanently displayed a Telegram handle input and Save
button even after successful persistence. This was confusing. The fix:

- With no saved alias: shows optional handle input and Save; blank values do
  not generate an attribution line.
- With a saved alias: displays the normalized `@handle` as read-only text,
  with **Edit** and **Remove** buttons rather than an input.
- Edit reopens the existing handle in the input. Cancel retains the saved
  alias. Successful Save closes editing.
- Remove requires confirmation. The SharedPreferences key is **removed**
  (not replaced with a fake handle); new clipboard shares revert to the
  default SP-DECODE/Powered by Ghost Developer header without a personalized
  credit. Existing encrypted results remain unchanged.
- Persistence returns a Boolean to the UI; failed writes do not display a
  misleading Saved state.
- Edit/Remove/confirmation strings are present in all 14 locales.
- Source-level contract check in `tests/test_android_unity_release_contract.py`.
- User-device tests still required: reopen Settings after Save, Edit/Cancel,
  Delete/Confirm, copy JSON in Spanish and English and verify exactly one @.
