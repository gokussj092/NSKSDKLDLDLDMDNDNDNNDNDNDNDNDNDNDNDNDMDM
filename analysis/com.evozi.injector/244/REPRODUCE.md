# Reproduce from repository root

Use Python3.12.14 and the recorded research dependencies. Set PRIVATE_DIR to a restricted directory outside Git. For HTTP Injector, UPLOAD_ZIP refers to the original user archive. Do not commit input bytes.

```bash
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/audit_hmac_usage.py from-upload "$PRIVATE_DIR/http-injector" --upload "$UPLOAD_ZIP"
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/audit_hmac_usage.py scan "$PRIVATE_DIR/http-injector"
python analysis/_intake/hmac-auth-audit-2026-11-09/tools/test_audit_hmac_usage.py -v
python -m unittest discover -s analysis/com.evozi.injector/244/tests -v
```

The Speicers recipe pins documented build123; it does not silently replace it with another version. Verify hashes in generated/identity.json. No server authentication probe, HMAC-key recovery or input/output hook is part of this recipe.
