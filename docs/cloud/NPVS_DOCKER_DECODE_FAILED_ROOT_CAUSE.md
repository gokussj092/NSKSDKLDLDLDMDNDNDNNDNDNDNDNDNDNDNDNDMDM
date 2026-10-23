# NPVS `DECODE_FAILED` with password after successful Android prompt

## Incident diagnosis (2026-10-23)
Android correctly detected signed NPVS v5 passphrase framing and showed the
existing Cloud password dialog. The worker emitted `DECODE_FAILED` despite
the same authenticated format passing the source-tree unit tests.

**Root cause:** `engine.decode_file("npvs", ...)` selects the subprocess
`cloud/workers/python/npvs_bridge.py`, while the runtime worker image
`cloud/workers/python/Dockerfile` previously copied only selected bridge
files and omitted `npvs_bridge.py`. On the VPS, Python could not open the
bridge script. Since stderr is intentionally suppressed by the isolated
worker, the subprocess exited nonzero and was classified `DECODE_FAILED`.
The 1FTunnel bridge lived under `decoders/`, which the Dockerfile already
copies, so that integration worked.

## Resolution
- Add an explicit `COPY ... npvs_bridge.py` to the worker Dockerfile.
- Validate its presence and Python imports while building the image under the
  actual UID 65532 (nonroot), not just in source-tree CI.
- In C2 Docker topology tests, copy an entirely **synthetic** NPVS fixture
  generator to the ephemeral test container (never the built Docker image)
  and verify `PASSWORD_REQUIRED`, `AUTH_FAILED`, and successful complete JSON
  with the actual isolated worker and correct password.
- Add a source-to-image packaging regression test.

No modification to the Android dialog, signing, catalog, HTTP Custom or
1FTunnel is necessary. Do not introduce local NPVS decryption in the APK.

## VPS rollout and validation
After CI passes, deploy/rebuild **the worker** (not only API/web) from the
correct PR branch. Prefer the deployment's documented updater, explicitly
selecting `worker`, and verify the container has the bridge after the
image rebuild. Never reveal input files, passwords, tokens, decrypted results
or environment variables in operational logs.

The public endpoint retains the existing API contract. Once the corrected
worker runs, a v5 passphrase export produces `PASSWORD_REQUIRED` when
credentials are missing, `AUTH_FAILED` on wrong password, and full JSON for
the correct password. A result from old running containers does not prove
the source commit is incorrect; compare deployed image and active worker.
