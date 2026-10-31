# SP-DECODE — Compatible export variant coverage (2026-10-31)

This is a developer QA record, **not** a declaration of Play production readiness. Only the current development branch is in scope; `main`, Play Console and the VPS are unchanged.

## Data protection and provenance

- The owner's supplied configurations and any resulting connection credentials remain outside GitHub. Do not add raw profiles, decrypted JSON, credentials, fingerprints of private files, or private QA archives to this repository.
- Round-trip checks run locally on supplied samples and independently generated synthetic data. Successful cryptographic round trips **do not demonstrate** that a specific vendor app version will import, edit, or connect with the result.
- The converter may reset **local, observed** expiration metadata only after the original authenticated container has been read and only while recomputing dependent cryptographic authentication. This does not renew subscriptions or override remote VPN-provider authorization.

## Observations and status

| Source family | Read support | Compatible export | Remaining verification |
|---|---|---|---|
| HTTP Injector standard-IV AEAD (sampled build 244) | Existing | Reset observed outer/inner `configExpiryTimestamp` integer to 0; preserve the field, recompute Argon2-bound inner AEAD and outer HMAC, and verify output with the existing `open_profile` reader. Five locally supplied samples independently passed a decrypt–rewrite–decrypt round trip. | Original HTTP Injector app import, editing, and policy behavior |
| Dark Tunnel 1.0.26 `SSH_DNSTT` | Existing | Extend the audited open converter using `sshDnsttTunnelConfig`; reconstruct SSH and inject/DNSTT properties from original encrypted leaves, reject unexpected sections and empty DNS tunnel identifiers, no banner, no changes to expirations other than the previously audited zero-expiry guard. One locally supplied sample preserved 13 field values in an independent candidate check. | Original Dark Tunnel app import, editor and connection; DEX field name alone does not prove the entire nested schema |
| HTTP Custom classic 32-token payload | Existing read-only presentation | **Not enabled**: some nonempty original tokens are omitted by the presentation reader. A direct migration from the rendered JSON would discard unknown parameters. | Map all tokens and prove original import of a lossless destination; never silently omit unknown positions |
| HTTP Custom `cfg.content` 32-token payload | Existing read-only presentation | **Not enabled**: this is not authenticated HCX4/HCCFG10/build-899 layout. The modern writer requires a validated HPC1 profile and complete native semantics. | Audit source token variants, encrypted sidecars and a true lossless target layout |
| NPVS v5 app-key mode 2 | Existing | Existing converter only: when a policy cannot be represented in observed open `NPVO1`, retain the successful decode and mark the export unavailable, rather than discarding policies or inventing support. | Recover authenticated metadata, determine exact per-file rejection and run owner Android import tests |

## Relevant implementation

- `cloud/workers/python/exports/ehi.py`: constrained numeric timestamp replacement in both layers, with strict type checks and authenticated rewrapping.
- `cloud/workers/python/exports/injector.py`: post-write check that an observed exterior expiration field is no longer active.
- `cloud/workers/python/exports/dark.py`: an explicit candidate for the audited `SSH_DNSTT` enum, using `sshDnsttTunnelConfig`; checks original decrypted field equivalence.
- `tests/test_compatible_export.py`: source-bound synthetic regression cases added for EHI expiry reconstruction and DNSTT field preservation. Local independent proofs are **not** substitutes for a full repository test run.

## Release gate

1. Run repository Python regression suite and verify older SSH/VLESS, HC, EHI and NPVS flows remain unchanged.
2. For each owner-controlled original profile, import the candidate with the original vendor app, check the editor and all connection fields, verify no undesired expiry/banners, and report exact application build.
3. Keep unsupported variants rejected until their source/destination semantics are verified. Do not infer exportability from successful display-only decryption.
4. Deploy VPS and publish an Android release only after the above verification, separately from this code change.

Status: **development branch only, QA pending**.
