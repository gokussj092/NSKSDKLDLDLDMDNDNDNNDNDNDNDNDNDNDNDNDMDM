# Xhypher Tunnel Pro — Cloud file and text carriers

## Verified scope

- Canonical file extension: `.xhypher` (existing C0/C8 route, unchanged).
- Complete encrypted text exports: `xhyphertunnelpro://BASE64` and `xhypher://BASE64` using the existing RENZ/Xhypher codec.
- Files renamed to `.hat` or `.bdnet` that contain one of these complete encrypted Xhypher carriers are routed to the canonical `.xhypher` engine **only after exact vendor scheme, strict Base64, and full block-envelope checks**. No attempt is made to try several unrelated encryption keys.
- The original file suffix remains in the API `format` field; decoder metadata identifies the real Xhypher engine. Genuine `.hat` (HA Tunnel Plus) and `.bdnet` (BD NET) retain their native engines, including Cloud complete HA Tunnel output.
- A `xhypher://` value containing a *short reference* is **not a locally encrypted export**. The vendor may require a remote repository lookup; this implementation neither resolves it nor claims short-link support. Only full encrypted carriers are supported.

## Original defect and privacy boundary

Two owner-provided files named with `.Bdnet` and `.hat` were identical and began with `xhyphertunnelpro://`. Import-by-suffix previously sent them to BD NET or HA Tunnel and returned a decryption failure, despite the available Xhypher text decoder. The third owner sample was an actual `.hat`, which must not regress.

No private source files, configuration contents, decrypted records, hosts, passwords, account identifiers or ciphertext are committed to the repository or used as test fixtures. Automated tests use the existing **synthetic** Xhypher golden fixtures.

## Android and rollout

`cloud/web/content/text-formats.json` publishes both prefixes as Cloud text metadata pointing to the vetted `xhypher` suffix. Server VPN catalog version 51 triggers the encrypted Android format-cache refresh. The existing Cloud Android build reads these server-supplied metadata routes and sends raw text to the unchanged private text bridge.

The `.xhypher`, `.hat` and `.bdnet` entries remain in the file catalog: no new file extension is invented and there are still 254 file routes. Native C0 engines, Android offline code, API session authorization, provider controls, and secret handling remain intact.

Deployment (only after GitHub Actions / owner approval):

```bash
sudo spdecode backup
sudo spdecode update all main
sudo spdecode status
curl -fsS https://api.spdecode.xyz/api/v1/ready
```

In the Android app, use **Actualizar catálogo** so the new text prefixes become visible. The actual VPS must first be updated and healthy; committing this change does not deploy it.

## Dark Tunnel text aliases in the same release

The Cloud text catalog already published `dt://`, `dtunnel://` and
`dark://`, but did not publish the full application-name alias
`darktunnel://`. The private worker likewise lacked that explicit dispatcher
route. Version 51 adds the fourth alias to both the Cloud catalog and worker,
using the existing `DARKTUNNEL.py` decoder (no new cryptographic method).
Android already recognizes schemes containing `dark`; a refreshed catalog
now advertises this exact alias. A synthetic AES-CFB/MessagePack fixture tests
all four schemes through the isolated Cloud text worker, preserving identical
output and rejecting malformed input.
