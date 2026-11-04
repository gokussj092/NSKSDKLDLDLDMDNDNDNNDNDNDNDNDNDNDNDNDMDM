# MAYA TUN PRO — investigation (2026-11-04)

## Inputs and distinction of evidence

User supplied a Python script and a `maya://` sample; the script contained a personal GitHub token. The credential was **never used or committed**. It must be revoked and replaced with a scoped credential only if repository access is authorized.

Existing project code: `decoders/Python/maya.py` and `decoders/Python/_noobcrypt.py` decode `.maya` files through AES-256-CBC (IV first) and authenticated AES-GCM inner fields. The Python user script correctly distinguishes URI ChaCha20-Poly1305 (nonce 12 bytes, 16-byte tag) from the separate encrypted file.

Local sample `maya://` decrypts with the observed Maya key to a fixed 16-character filename identifier; no actual VPN configuration is contained in the URI. The corresponding URL is strictly derived under `https://api.github.com/repos/janatshaban/noob_files/contents/config/mayatun/` with suffix `.maya`.

## Real-network attempts

- Container DNS to `api.github.com` was unavailable in this execution environment (temporary name resolution failure).
- GitHub connector queried the repository root, per-ID Contents URL, directory Contents URL and raw URL without any user credential; each returned HTTP 404.
- These checks do **not** establish that the target is deleted; GitHub intentionally presents private repositories as 404 to unauthenticated visitors.
- As a result there is no successful real download, no authenticated/complete remote JSON, and **no Server VPN catalog enablement**.

## Cloud-only implementation

- Server-side `maya://` authenticated ChaCha20-Poly1305 reference parser.
- Fixed GitHub host and file path; DNS and TLS verification pinned to an approved public IP and no redirects, arbitrary URLs, user supplied headers or query strings.
- Optional `CLOUD_MAYA_GITHUB_TOKEN` only from server environment; never from Android, URLs, logs, code or fixtures.
- GitHub Contents metadata exact-path and MIME-independent Base64 validation; second Base64 recognized but not decrypted in the broker.
- Existing `.maya` offline worker performs complete CBC decoding plus inner GCM authenticity checks, preserving full JSON (no partial previews).
- Text format advertised in Cloud catalog; requesting it without authorized source access returns a failure rather than fabricated configuration.

## Scope

No APK/AAB build, VPS deployment, private credential use or subscription account tests. No evidence of a browsable or downloadable complete Server VPN catalog. Changes retained on an isolated branch for CI and review.
