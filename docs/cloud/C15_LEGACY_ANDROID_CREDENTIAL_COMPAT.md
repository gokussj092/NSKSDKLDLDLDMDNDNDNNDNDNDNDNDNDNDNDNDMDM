# Compatibility of old SP-DECODE APKs with new Cloud password methods

Applies only to the public decode/file and decode/text gateway in PR #96.
No Play release, UI redesign, database migration or VPS deployment.

## Feature negotiation
New Android builds send `X-SPDecode-Credential-Prompts: 1` from the existing
native C++ HTTPS transport on **decode/file** and **decode/text** requests.
Older APKs do not send this header. The server treats any missing, unknown or
invalid value as a legacy client. The existing
`X-SPDecode-App-Version` may still be recorded as bounded telemetry, but is
never used as a proxy for feature support.

The capability header only chooses presentation of an error AFTER the worker
has authenticated and classified the file. It does not waive authorization,
Play Integrity, rate limits, encryption, password checks or resource caps.

## Compatible error responses
| Worker error | Format | Legacy APK error | New APK error |
|---|---|---|---|
| PASSWORD_REQUIRED / AUTH_FAILED | npvs file | NPVS_PROTECTION_UNSUPPORTED | original |
| PASSWORD_REQUIRED / AUTH_FAILED | 1ftnl/tut file | UNSUPPORTED_FORMAT | original |
| PASSWORD_REQUIRED / AUTH_FAILED | NPV/1FTunnel text | UNSUPPORTED_FORMAT | original |
| Password/HWID codes | hc file | unchanged | unchanged |
| Password codes | ua file or text | unchanged | unchanged |

Both mapped error codes were already supported in previous SP-DECODE APK
localization. Status remains HTTP 422: never a fake successful JSON document.
Older APKs still cannot render a newly introduced dialog or a custom update
banner; this compatibility ensures a bounded supported error response rather
than a non-actionable new credential prompt. Modern APKs handle precise error
codes and open their existing native dialogs.

Unauthenticated, unsigned, tampered, unsupported or failed formats must never
be retried under a weaker decoder. Successful JSON, including password-free
NPVS, is passed through byte-for-byte by the gateway. Internal counters keep
the actual worker result rather than the compatibility response code.

## Tests
`cloud/web/tests/decoder-client-compat.test.mjs` covers strict negotiation,
known format scope, legacy errors and unchanged HC/UA/other outcomes.
`cloud/web/tests/c3-security.test.mjs` tests real gateway admission with
old/new request headers and a complete password-free NPVS result.

Deploy the server only after passing C3 and Android CI. Old APKs do not need
reinstallation to receive the legacy response mapping; new APKs require their
newly compiled native header and password dialog handlers.
