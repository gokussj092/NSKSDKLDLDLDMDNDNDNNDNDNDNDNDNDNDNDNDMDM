# Hardware security and closed Google Play testing

V1 URLs, response formats, maintenance controls and the panel's temporary Play
admission switch remain available. V2 does not inherit the temporary V1 Play
bypass. The switch that disables Google verification is not a device attestation
check and does not itself disable the entire V1 API.

## Profiles

| Profile | Admission and request requirements |
| --- | --- |
| V1 compatibility (default) | Existing bearer/session and panel policies; atomic throttles, global work budgets, shared concurrency, and isolated worker caps. Play signing fingerprints are checked when configured. |
| V1 bound (`CLOUD_V1_REQUIRE_BOUND_SESSION=true`) | Obtain a V2 session, then use V1 routes with the same operation signatures, hardware key and sensitive-action headers. Old bearer-only sessions are refused. |
| V2 (default strict) | Google Play app, signer, license, version, SDK and activity; hardware-attested key; exact per-request signatures; fresh Standard Integrity for operations 4–9 and 12. |

`CLOUD_LEGACY_API_ENABLED=true` preserves V1. Explicit `false` retires V1 through
Next's proxy. Nginx continues routing V1 so operators can preserve it. General and
per-service panel maintenance controls continue applying to V1 and V2 handlers.
Hardware verification is independent of LIAPP and of the V1 Play switch.

## Prepare a closed testing deployment

1. Link the Google Cloud project to Play Integrity in Play Console. Enable the
   device attributes, Strong Integrity and recent device activity verdicts.
   Use the **Play App Signing** SHA-256 certificate, not merely the upload key.
   Enrolled testers must install the build from the closed testing Play link.
2. Apply LIAPP to the intended release artifact, then sign/upload according to
   LIAPP's AAB/Play instructions. Test the final Play-delivered build, including
   JNI registration, Keystore, Standard Integrity and provider preparation.
   An external or re-signed APK is not equivalent to the Play-installed build.
3. On the VPS, prepare configuration (this command does not restart services):

   ```sh
   sudo python3 cloud/infra/vps/prepare-hardware-security.py \
     --project-number YOUR_LINKED_GOOGLE_PROJECT_NUMBER \
     --play-certificates YOUR_PLAY_APP_SIGNING_SHA256 \
     --level tee
   ```

4. Start the private verifier and recreate the web service:

   ```sh
   docker compose --project-name spdecode --env-file /etc/spdecode/cloud.env \
     -f cloud/compose.yaml --profile hardware-security up -d --build
   ```

5. Verify on physical devices through Google Play. The default device floor is
   Android 13 and all attested OS/vendor/boot patches must be within 12 months.
   Missing SDK/activity verdicts fail closed. Configure these labels before
   enabling the strict build. Use `--level strongbox` only when the tester/device
   population supports it; that profile never falls back to TEE.
6. Exercise both existing V1 panel controls and V2 before changing any compatibility
   policy. No automatic change to the panel's Play admission setting is made.

The verifier needs outbound HTTPS to `android.googleapis.com` for fresh
revocations. Both revoked and suspended attestation certificates are refused.
It accepts only the bundled official Google trust roots. Update the vendored
upstream revision and roots together when Google rotates trust anchors.

For staged backend migration only, `CLOUD_KEY_ATTESTATION_REQUIRED=false` and
`CLOUD_ACTION_INTEGRITY_REQUIRED=false` retain the earlier V2 protocol. These
are deliberate reductions of security, never automatic outage fallbacks.
New strict V2 rejects earlier clients that cannot supply the required evidence.

## Protocol and enforcement

- Operation 1 returns the server's fresh hardware challenge when a key is not
  registered. The client generates a new P-256 attested key and operation 2
  supplies its chain and a Google nonce bound to that new key. Registrations last
  at most 24 hours. Certificate verification occurs only on the private backend.
- A registered key must prove possession on every call. Session rotation does
  not reset the key's minute/day work budget. The API rejects a revoked key on
  every request (`spsec:revoked:<SHA256-of-base64url-SPKI>`). Keep revocation flags
  outside ephemeral Redis backups if durable operator revocation is required.
- Operation 16 creates a 120-second, single-use action challenge bound to the
  session, key, operation and exact body SHA-256. The Android Standard Integrity
  token carries its `requestHash`. Submit `X-SP-Action-Challenge` and
  `X-SP-Action-Integrity` alongside the ordinary request signature. Reuse, body
  substitution and a different operation are refused before invoking the worker.
- Shared Redis leases last 300 seconds, exceeding the worker's bounded execution
  deadline. At most four gateway jobs are reserved globally and two per session.
  The worker independently enforces four active jobs, even if a lease is lost.
  Only one memory-heavy catalog job runs at once. Nginx limits large file uploads
  to twelve concurrent requests across V1/V2 before buffering their bodies.
- A key ID identifies a registered key, not an immutable physical device. New
  keys, reinstallations and device farms require enrollment limits and activity
  analysis. This does not establish a unique person or the truth of arbitrary
  sensor/payload values.

## LIAPP and remaining verification

LIAPP can add packing, tamper/hooking detection and transport protections, but no
LIAPP SDK, credentials, paid license, or vendor server-verdict API is fabricated
in this repository. Its final protected artifact must be tested on the closed
track. Client-side detections do not replace backend authorization.

CI verifies signed synthetic chains against test-only roots, rejects those roots
with the production verifier, tests request substitutions/replay and exercises
actual Redis Lua concurrency. These tests are not Google certification, a real
hardware penetration test, or proof that a genuine phone cannot be automated.
An authorized phone may still serve as a signing/attestation oracle. No native
packer, language choice, AI notice, or client-side shared secret eliminates that.
