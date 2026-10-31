# SP-DECODE — Android C++ boundary and dependency advisory audit

Date: 2026-10-30. Branch: `security/hpke-native-cpp-migration`.
Scope: repository source, Gradle/Node/Python manifests, published GitHub
advisories, and the previously successful isolated native/Android compilation.
**This is not a physical-device penetration test or a live VPS deployment.**

## Android Cloud release boundary

The distributed Cloud APK compiles an allowlisted source copy through
`prepareCloudOnlySources` in `android/app/build.gradle.kts`. It excludes
`com/ghostdeveloper/spdecode/parity/**` except the Android decoder catalog
display helper. `SecureAssetVault.kt`, `SpecialCrypto.kt`,
`IndependentCrypto.kt` and offline secrets/materials are **not** compiled
into the Cloud release artifact. Offline/legacy repository code remains in Git,
but it is not the same as a shipped Cloud security regression.

| Component | Actual place | Review conclusion |
| --- | --- | --- |
| V2 HPKE X25519, HKDF, AES-GCM, recipient pin | `spdecode_hpke.cpp`, `spdecode_transport.cpp` | Native. No plaintext fallback. |
| HTTPS transport, pin/signature policy, route allowlist | `spdecode_transport.cpp` | Native JNI; origin configured in native CMake. Public origin is not a secret. |
| PoP canonical message and ECDSA request signing orchestration | `spdecode_security.cpp`, `spdecode_transport.cpp` | Native with Android JCA secure-key operations through JNI. |
| Session cache, expiration, stale-401 invalidation, bearer-specific Standard policy | `spdecode_session.cpp` | Native; Kotlin bearer copies still necessary for boundary API. |
| Cloud catalog P-256 ECDH/HKDF/AES-GCM tag verification | `spdecode_catalog.cpp` | Native, positive/negative interoperability tests passed. |
| Android Keystore alias selection, enrollment policy, StrongBox fallback | `spdecode_keystore.cpp`, `spdecode_keystore_policy.cpp` | Native policy + Android platform calls; backend validates attestation. |
| Non-exportable private key generation, ECDSA signing, certificate extraction | `CloudKeystorePlatform.kt` + JCA/JNI | Intentionally Android-only provider; moving private keys to a C++ heap would weaken protection. |
| Classic/Standard Play Integrity token requests | `CloudDecodeClient.kt` | Must use official Google SDK and asynchronous Android APIs. Server verdict is authoritative; native format checks are not an admission substitute. |
| Ephemeral catalog P-256 keypair generation | `CatalogEnvelope.kt` | **Remaining possible native hardening.** JCA creates ephemeral key; temporary PKCS#8 bytes cross JNI before zeroization. No server or Keystore installation private key is exported. |
| Legal consent, credential dialog/policy and JSON rendering | `CloudLegalConsent.kt`, `CloudCredentialPolicy.kt`, UI | User/platform presentation/validation remain Kotlin; the server must enforce sensitive policy. Do not mistake an obfuscated UI branch for a security boundary. |
| Encrypted local history, credential vault, server catalog cache, NPV identities | `SecureDecodeHistory.kt`, `DevicePrivateCredentialVault.kt`, `ServerVpnSecureCache.kt`, `NpvsIdentityVault.kt` | AndroidKeyStore AES-GCM and file I/O are intentionally Android platform operations. Audit future key loss, concurrency, IV and backup risks on real devices. |
| Runtime anti-debug/Frida/overlay/abuse checks | C++ basic debugger + signing check | **Not a claim of comprehensive RASP**; no untested blanket blocking before device compatibility review. |

**Finding:** Do not claim that absolutely all security-sensitive Kotlin/Java
code has moved to C++. JNI, Play SDK and KeyStore are trusted platform
boundaries. The native catalog ephemeral keypair can still be further reduced.
The correct goal is native ownership of proprietary crypto/protocol and
server-enforced trust, not removing every use of `javax.crypto` in the APK.

The prior source-only CI checks passed for commit `0c8cd7a`:
- Native C++/Node interop and negative cases: GitHub Actions `41149344926`.
- Release R8, four ABI compilation, JNI signatures, AAB: `41149344918`.
**Neither runs physical-device StrongBox or Play Integrity admission.**

## Confirmed published dependency advisories

1. `website/package.json` previously pinned `next@16.4.0`, affected by
   `GHSA-673q-mjm6-r5xr` and `GHSA-2464-fhr4-w9xw`, plus
   `GHSA-p3m5-59mp-jv5r`. Fixed in Next >=16.4.1.
   Patch branch pins **16.4.3** in both website and Cloud web.
2. React Server Components `react-server-dom-*` versions up through
   19.3.0 were affected by `GHSA-xqc2-xf4c-x3h3`; patched 19.3.1.
   Website previously directly pinned React/React DOM 19.3.0; the Cloud
   package used ranges. Patch branch pins React/React DOM **19.3.1** in
   both web packages. Actual transitive `react-server-dom-*` resolution
   still needs a fresh lockfile and `npm audit`.
3. Root worker `requirements.txt` and the Dark Tunnel laboratory pinned
   `msgpack==1.1.1`. `GHSA-j586-36cw-2gc2` affects <1.2.3
   (denial of service through memory leaks) and 1.2.4 adds October 2026
   memory-allocation hardening. Both manifests now pin **1.2.4**.
4. `requests==2.32.4` meets the published fix for
   `GHSA-9hjg-9r4m-mvj7`; no change based on that advisory.
5. `cloud/attestation`'s `protobuf-javalite==4.28.3` is newer than
   the 4.28.2 patch threshold for `GHSA-735f-pc8j-v9w8`.
   `bcpkix-jdk18on==1.86` is newer than earlier Bouncy Castle
   hardening fixes; this does not constitute a full transitive scan.

References:
- https://github.com/advisories/GHSA-673q-mjm6-r5xr
- https://github.com/advisories/GHSA-2464-fhr4-w9xw
- https://github.com/advisories/GHSA-p3m5-59mp-jv5r
- https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3
- https://github.com/advisories/GHSA-j586-36cw-2gc2
- https://github.com/msgpack/msgpack-python/blob/main/CHANGELOG.md

## Dependabot access and verification gap

The installed GitHub connector supports repository files, PRs, workflows and
commits, **but denied** the authenticated `/dependabot/alerts`,
`/code-scanning/alerts`, `/secret-scanning/alerts`, and SBOM endpoints.
Consequently the real private inbox counts, alert numbers, dismissals,
affected manifest paths, and remediation status were **not verified**.
The repository currently has **no** `.github/dependabot.yml` updater config,
which is separate from GitHub's automatic vulnerability alerts.
Do not infer zero alerts from a missing Dependabot updater config.

Open the actual repo Security > Dependabot alerts in the logged-in GitHub UI,
and compare alert ID, severity, affected dependency, manifest, introduced/fixed
version and state on default branch. Then inspect Code scanning and Secret
scanning separately. Do not dismiss alerts merely because a fix exists
in this unmerged branch.

The Cloud and website projects currently have no committed npm lockfiles.
Before any web redeploy: install fresh dependency trees in isolated CI
containers, commit/review correct lockfiles if the project policy allows it,
run `npm audit --omit=dev` plus build/tests on **each** app, and inspect the
final `npm ls next react react-dom react-server-dom-webpack` resolution.
For worker: `python -m pip_audit -r requirements.txt` and Dark engine fixtures.
The Docker web image currently runs `npm install --no-audit`; this source
dependency patch does **not** change the VPS's installed package versions.
Updating npm/pip source manifests does not close GitHub alerts until the
affected default branch, dependency graph and deployments are updated.

## Operational safeguards

- This branch's dependency patches must **not** automatically deploy the
  Cloud worker, Next.js web or existing VPS images.
- Rebuild and deploy only with a controlled backup/rollback and functional
  tests. Confirm vulnerable package versions are absent in the real images.
- Keep release signing keys, Cloud HPKE private keys, Firebase service keys
  and any bearer tokens out of repository files and diagnostics.
- `tests/test_dependency_security_floors.py` is a zero-network guard against
  reintroducing the known direct-version vulnerabilities. It cannot replace
  GitHub Dependabot alerts, SBOM scanning, lockfile scans or device testing.
