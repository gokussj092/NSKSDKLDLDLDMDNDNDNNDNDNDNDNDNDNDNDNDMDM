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
