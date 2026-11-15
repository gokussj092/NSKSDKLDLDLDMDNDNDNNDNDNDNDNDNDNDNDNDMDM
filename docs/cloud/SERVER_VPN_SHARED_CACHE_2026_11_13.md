# Shared Server VPN catalog results (2026-11-13)

The Android API and HPKE response contract are unchanged. This is **server-side**
caching on the authenticated fixed-provider catalog endpoints, including NUR.
A valid result serves future authorized users for four hours; there is no
per-user cache or shared HTTP/CDN cache. Requests still authenticate, rate-limit,
check consent, provider switches and maintenance. The response gets a new
request ID. User-supplied files, links and password/HWID fields are excluded.

- Four hours since successful computation; renew from 3h45. One background
  refresh at a time, preferentially when the global worker queue is idle. The
  API continues serving the valid old result during renewal. The timer ticks
  every ten seconds; Redis leases deduplicate concurrent requests and scheduled
  work. At expiry no old result is served. Failed jobs are not cached; validated MKK Hyper partials are the sole partial-result exception.
- Only recently requested catalog IDs (last request within 24 hours) are
  proactively renewed, so new catalog integrations do not flood the VPS;
  the next authorized request reactivates demand. This lightweight demand
  marker is ephemeral Redis state and does not include user identity.
- Standalone SSH-account catalog IDs (`opentunnel-ssh`, `speigo-vpn-ssh`)
  remain excluded. MKK Hyper is included at the owner's request, using the
  existing fixed-source, session-gated broker. Only successful complete or
  explicitly validated partial MKK results are cached; source failures and
  warnings remain intact. Refresh may upgrade a partial result to complete;
  a still-valid complete result is not replaced with a partial. No new
  personalized sources or user-supplied inputs may enter this cache.
- Storage revision 2: private, uncompressed plain JSON in the existing
  named volume `server-vpn-results` (0700 directory, 0600 files). No gzip,
  AES-GCM or cache-key derivation on reads or writes. No new RAM cache,
  service or polling. Existing HPKE transport protection remains unchanged.
  The entry stores schema, provider, revision, computed timestamp and result;
  validates JSON and freshness before use and issues a fresh request ID.
  The existing six MiB per ordinary entry, 32 MiB for MKK and 256 MiB
  aggregate disk limits are unchanged; uncompressed files will generally
  take more disk/OS page-cache space and may hit the disk budget sooner.
  Oversized results use the normal path. No catalog body in Redis.
  Atomic writes and opportunistic expiry cleanup remain. Old .bin entries
  are never decoded or migrated and are removed on subsequent writes;
  the first new request may be a cold miss. Deployment/catalog/provider
  revisions and operator revision still invalidate cached results.
  No cryptographic integrity or confidentiality at rest: local privileged
  access, compromised runtime users and backups can expose or alter the
  data. Do not include this disposable volume in backups or serve it via
  public routes. Cache only shared catalogs the operator is authorized
  to store and distribute; do not store user-specific credentials or
  private inputs. For sensitive catalogs requiring encryption at rest,
  disable the shared cache instead of using this plaintext mode.
- A failed refresh preserves a still-fresh result and backs off five minutes.
  If no fresh data exists, return a controlled error rather than inventing data.
  On successful refresh, TTL resets, not extended by read hits.
- The scheduler runs through Next's Node runtime instrumentation, not from a
  public endpoint. It uses the same fixed broker and isolated decoder worker,
  shared global worker slot accounting and sanitized diagnostics. No new
  external vendor URLs, worker egress, ports or API client contract changes.
- Default compose switch `CLOUD_SERVER_VPN_CACHE_ENABLED=true`; set false
  in `/etc/spdecode/cloud.env` and recreate web to disable. Increment
  `CLOUD_SERVER_VPN_CACHE_REVISION` to invalidate all stored data.
  No need to compile Android for this change. Do not erase Redis security
  state to clear catalog cache. No VPS deployment from this commit. The format change intentionally incurs a one-time cold refill.
- Real throughput and proactive refresh timing depend on upstream/worker
  health and load. This does not guarantee instantaneous delivery if a
  catalog expires while the server is busy.

Validation: source checks, dedicated cache test suite and web image build in
GitHub Actions. Fixtures do not contact vendor endpoints, and do not certify
actual VPS throughput or third-party permissions. A plain cache reduces per-hit CPU work but cannot guarantee lower total CPU/RAM/disk consumption or eliminate transport/client-side latency.
