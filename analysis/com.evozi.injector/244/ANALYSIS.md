# HTTP Injector 6.5.0/build244 — HMAC usage audit

Scope: identify presence without collecting service authentication material. Package/build and SHA256 are in generated/identity.json. Only82 methods are visible in the base DEX. Native markers are present; this inventory does not cover all application logic or establish how native/protected code behaves.

Observed: 1 DEX, 82 methods visited, 0 Mac.getInstance references, 0 Mac.init references, 0 Mac.doFinal references and 15 native libraries inspected for fixed algorithm markers. These are static counts, including dependency code. No execution or protocol-role assertion follows from their presence.

The scanner retains only fixed algorithm names, counts, hashes, identity and explicit uncertainty. It does not collect class/function operands, function inputs/outputs, private keys, tokens, generated HMAC secrets or decrypted VPN profiles. No hook or vendor APK/native code executed. No connection was made to a VPN/authentication endpoint.

`connection_authentication.status` remains UNCONFIRMED. No keys were extracted; no catalog, decoder, file export or service route was activated. The audit rule is documented in AGENTS.md and section2.2 of METHOD_EVIDENCE_POLICY.md; no new automatic CI gate or F7 execution is claimed.
