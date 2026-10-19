# SP-DECODE Cloud — Backend Android & site (C0–C6)

This directory contains the evolving **server-side architecture for SP-DECODE Android**, not a browser-based decoder. The Android UI is unchanged and the Python bot is not modified.

**State: development branch; no public release or production deployment.** Live processing needs real Google Play Integrity, HTTPS, a registered Android app, Redis and backend secrets. Existence of 240 catalog routes does not certify exporter-version compatibility.

## Structure

| Directory | Responsibility |
| --- | --- |
| `web/app` | Next.js App Router public pages (`/`, `/features`, `/docs`, `/privacy`, `/status`) and private admin UI |
| `web/app/api/v1` | Android-only C3/C3.5 decoding API, session challenges, health and capabilities |
| `web/app/api/admin` | C6 operator login, session status, maintenance and logout |
| `web/lib/c6-admin-auth.mjs` | Server-side scrypt password verification, signed cookies, CSRF and throttling |
| `web/lib/c6-admin-api.mjs` | Private operations (status, read-only provider flags, maintenance) |
| `web/lib/c6-ops-store.mjs` | Redis non-content aggregate metrics and maintenance flag |
| `workers/python` | Private authenticated original Python/Node/PHP engine adapters |
| `contracts/v1/openapi.json` | Public Android Cloud API contract |
| `compose.yaml` | **Development-only** Docker topology: loopback web, private Redis and private worker |

## Site / operator setup

The site is informative and **never accepts decoder uploads via browser**. `/api/site/status` returns only the generic prelaunch state.

By default, the admin UI is **disabled**. Operator access requires all of these server-only variables:

- `CLOUD_ADMIN_ENABLED=true`
- `CLOUD_TRUST_PROXY=true` and a correctly configured HTTPS reverse proxy that overwrites `X-Real-IP`
- `CLOUD_ADMIN_PUBLIC_ORIGIN=https://<actual-hostname>`
- `CLOUD_ADMIN_SESSION_KEY`: unique random secret, 32+ characters, not reused for API bearer/worker access
- `CLOUD_ADMIN_PASSWORD_SCRYPT`: salted hash; generate with `node cloud/web/scripts/hash-admin-password.mjs` from stdin, never pass plaintext in CLI arguments
- `CLOUD_REDIS_URL`: private Redis reachable from Next.js

The login has IP/global attempt limits, 30-minute session, HMAC cookie `HttpOnly; Secure; SameSite=Strict`, Redis revocation and exact HTTPS Origin/CSRF checks. The UI does not contain secrets and does not permit changing decoder algorithms.

**Maintenance controls:** The operator can temporarily set/clear `spc6:maintenance` in Redis; it rejects new decode/session requests. Development Redis deliberately has no persistence, so for deployment use `CLOUD_FORCE_MAINTENANCE=true` for an externally managed hard stop that the dashboard cannot override. Production should provision durable and HA operational controls.

`CLOUD_PUBLIC_SITE_INDEX=false` disables search indexation until public launch. Site copy and privacy notice are provisional and need legal/operational review.

## Development checks

```sh
cd cloud/web
npm install --no-audit --no-fund
npm test
npm run build

# From repository root:
docker compose -f cloud/compose.yaml config --quiet
```

Relevant checks: `.github/workflows/cloud-c6.yml` plus C3, C2, C1, C4 and C5 checks. The C6 suite covers malicious origins, cookie tampering, session revocation, rate limits, maintenance, anonymous metrics and frontend compilation.

## Boundaries

- The Android native HTTPS library is named **`libspdecode.so`**.
- Server signing keys, vendor decryptors, provider URLs, passwords and Play service-account credentials **must never enter the APK, frontend bundle or logs**.
- `CLOUD_API_ENABLED`, remote importer toggles and `CLOUD_ADMIN_ENABLED` are all disabled by default; never turn them on without provisioning server security and validating the deployment.
- No production admin login should be exposed without additional reverse-proxy restrictions (VPN/IP allowlist, MFA/SSO), monitoring and legal documentation.
- C7 and C8 cover device-to-server parity validation, integration stress, operations, release controls and rollback. C6 alone is **not** approval for production.

Architecture history and detailed implementation: `docs/cloud/C0_BASELINE.md` through `docs/cloud/C6_IMPLEMENTATION.md`.

## C7 integration and release gate

`cloud/tests/c7-e2e.test.mjs` runs synthetic Play/Redis admission through the **real C2 private HTTP worker** and compares raw output to independently executed original source scripts. `cloud/tests/c7_vectors.py` also covers protected HC, text and NUR catalog inputs; C2's 60-case baseline remains separate. `.github/workflows/cloud-c7.yml` builds the Android Cloud APK and audits the binary. The production gate `python scripts/cloud_c7_release_gate.py --production` must **refuse** approval until real Play Integrity/device, VPS, provider samples, privacy and C8 operations are independently verified. See [C7 documentation](../docs/cloud/C7_IMPLEMENTATION.md).
