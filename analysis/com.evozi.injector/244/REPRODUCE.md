# Reproduce from repository root

Use Python3.12.14 and the recorded research dependencies. Set PRIVATE_DIR to a restricted directory outside Git. For HTTP Injector, UPLOAD_ZIP refers to the original user archive. Do not commit input bytes.

```bash
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/audit_hmac_usage.py from-upload "$PRIVATE_DIR/http-injector" --upload "$UPLOAD_ZIP"
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/audit_hmac_usage.py scan "$PRIVATE_DIR/http-injector"
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/test_audit_hmac_usage.py -v
python -m unittest discover -s analysis/com.evozi.injector/244/tests -v
```

The Speicers recipe pins documented build123; it does not silently replace it with another version. Verify hashes in generated/identity.json. No server authentication probe, HMAC-key recovery or input/output hook is part of this recipe.

## Pending server catalog source

Use the same private input directory prepared by `from-upload` above, not the repository. The canonical wrapper verifies the original ZIP SHA256 before running the static stages. Install/use pycryptodome 3.23.0 and host libzstd 1.5.7 in addition to the pinned audit dependencies; no installation or third-party API request is performed by this recipe.

```bash
python analysis/com.evozi.injector/244/tools/scan_catalog.py "$PRIVATE_DIR/http-injector" --upload "$UPLOAD_ZIP"
python -m unittest discover -s analysis/com.evozi.injector/244/tests -v
```

Stages preserved under `analysis/_intake/http-injector-catalog-2026-11-09/tools/`:

1. `inventory.py`: inspect selected ZIP members; write restricted native inputs and a URL inventory with query values/userinfo/long opaque segments removed. Only Evozi/HTTP Injector domains are considered; this is not a complete endpoint discovery mechanism.
2. `frame_inventory.py`: verify libdatajar SHA256; decompress its documented frame into a bounded output buffer with host libzstd; scan selected route/type literals. Never load the APK's library.
3. `metadata_inventory.py`: verify library/frame hashes, walk known partial maps/string-data, retain only selected server UI/model descriptors. Do not reconstruct methods or export arbitrary constants.
4. `historical/httpinjector_650_unpack_native.py`: unchanged, owned script from historical commit `03bc9fe3c20a464dd1ea3848850b2d0227f5f477`; recover two native containers as data. The wrapper restricts output permissions.
5. `recovered_inventory.py`: retain results of the four unsuccessful additional-layout validations and scan recovered data for redacted public URL candidates.

Expected private files: `catalog-inventory.json`, `frame-inventory.json`, `metadata-inventory.json`, `recovered-inventory.json`, `code-frame.bin`, `inputs/`, `unpacked/`. Only manually reviewed JSON summaries belong in `generated/`; never copy the input archive, decompressed frame, recovered binaries or arbitrary string pools to Git. Expected hashes and known failures are recorded in the reviewed summaries.

The observed static output is **not** a server catalog. A working remote test still needs a reconstructed, authorized server-list request and complete response, without reusing third-party signing secrets or bypassing access controls.
