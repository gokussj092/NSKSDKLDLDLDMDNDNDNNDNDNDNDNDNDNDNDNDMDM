# Speicers Pro VPN 104.1.20/build123 — HMAC usage audit

Scope: identify presence without collecting service authentication material. Package/build and SHA256 are in generated/identity.json. Speicers documentation already describes HMAC in the catalog/file-format path; that evidence is not VPN-connection authentication evidence.

Observed: 1 DEX, 41622 methods visited, 5 Mac.getInstance references, 4 Mac.init references, 5 Mac.doFinal references and 14 native libraries inspected for fixed algorithm markers. These are static counts, including dependency code. No execution or protocol-role assertion follows from their presence.

The scanner retains only fixed algorithm names, counts, hashes, identity and explicit uncertainty. It does not collect class/function operands, function inputs/outputs, private keys, tokens, generated HMAC secrets or decrypted VPN profiles. No hook or vendor APK/native code executed. No connection was made to a VPN/authentication endpoint.

`connection_authentication.status` remains UNCONFIRMED. No keys were extracted; no catalog, decoder, file export or service route was activated. The audit rule is documented in AGENTS.md and section2.2 of METHOD_EVIDENCE_POLICY.md; no new automatic CI gate or F7 execution is claimed.
