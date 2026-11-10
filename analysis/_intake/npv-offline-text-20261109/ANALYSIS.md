# Offline NPV text parity

The existing C++ port already handled the five modern aliases and signed
NPVS payloads. The Android text entry point missed the existing server
legacy `dns://` and standalone `npvs1:` representations. Both now route to
NPV before the generic NetMod detector. Pasted-text capacity matches the
2 Mi-character reference adapter; no network lookup is added.

DNS uses the existing JSON/npvs1 decoding. A standalone npvs1 JSON object
or array retains its structure. An opaque decoded scalar is returned as
`{"decodedText":...}` so the offline app's JSON-only result contract is
preserved without discarding the text. Base64 errors are reported as errors.

A nested explicit npvs1 object previously caught errors thrown while
recursively decoding child fields and could mistakenly preserve the whole
object as prose. Only JSON parse failures now take that fallback. Invalid
child Base64/UTF-8 or nesting errors propagate; no partial success.

The five modern URI aliases preserve complete JSON and authenticated binary
NPVS delegation. Case, Base64 alphabets/padding and Unicode are checked
against the Python reference, plus DNS/standalone npvs1 against npvt_links.
No new real NPV exports or APKs were supplied; version provenance remains
unknown and the evidence is deliberately in the unversioned intake area.
The existing README's 124.0.37 static findings were not re-investigated.

HMAC audit: signed NPVS file cryptography and inventory integrity are exercised
with synthetic material by the existing parity suite. This change concerns
text transport only. It neither observes nor changes authentication for a
VPN service, and captures no service/session authentication material.
