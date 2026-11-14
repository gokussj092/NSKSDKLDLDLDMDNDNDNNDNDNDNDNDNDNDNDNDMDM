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
  work. At expiry no old result is served. Failed/partial jobs are not cached.
- Only recently requested catalog IDs (last request within 24 hours) are
  proactively renewed, so new catalog integrations do not flood the VPS;
  the next authorized request reactivates demand. This lightweight demand
  marker is ephemeral Redis state and does not include user identity.
- Standalone SSH-account catalog IDs (`opentunnel-ssh`, `speigo-vpn-ssh`)
  and `mkk-hyper` are excluded because of account/subscription sensitivity
  and the exceptional size/partial-source contract. All other fixed-provider
  catalogs use the common mechanism when enabled. Never cache new personalized
  endpoints without additional privacy/authorization review.
- Data: gzip + authenticated AES-256-GCM, key derived with HMAC domain
  separation from the existing server-side signing secret. Private named volume
  `server-vpn-results` with 0700 ownership and 0600 files. No catalog body
  inside Redis. Maximum six MiB serialization per cache entry, 256 MiB
  disk budget; larger results still use the normal response path. Files are
  replaced atomically, expired files pruned on writes. Freshness and method
  revision are authenticated; deployment build ID, operator revision, provider
  revision/state and secret rotation invalidate old results.
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
  state to clear catalog cache. No VPS deployment from this commit.
- Real throughput and proactive refresh timing depend on upstream/worker
  health and load. This does not guarantee instantaneous delivery if a
  catalog expires while the server is busy.

Validation: source checks, dedicated cache test suite and web image build in
GitHub Actions. Fixtures do not contact vendor endpoints, and do not certify
actual VPS throughput or third-party permissions.
