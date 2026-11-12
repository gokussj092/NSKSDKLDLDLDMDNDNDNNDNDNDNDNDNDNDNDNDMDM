#!/usr/bin/env python3
"""Static identity and fixed updater proof; never executes APK code or logs values."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
UPDATER = "https://web.tunneldoom.space/config.json"
SIGNER = "12704504f5711f22d78ee436f38baeb90557c2fa72c4dfb281c766f59800461d"

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
              "status": "PENDING", "apk_executed": False, "raw_values_logged": False}
    try:
        from loguru import logger
        logger.disable("androguard")
        from androguard.core.apk import APK
        from androguard.core.dex import DEX
        spec = importlib.util.spec_from_file_location("doom_acquire", Path(__file__).with_name("acquire.py"))
        acquire = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acquire)
        data = acquire.fetch_xapk()
        result["distribution"] = acquire.analyze_bytes(data)
        with tempfile.TemporaryDirectory(prefix="spdecode-doom-proof-") as folder:
            private = Path(folder)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                target = "com.tunneldoom.http.apk"
                info = archive.getinfo(target)
                if not 0 < info.file_size <= 100_000_000:
                    raise ValueError("BASE_SIZE_LIMIT")
                body = archive.read(info)
            base = private / "base.apk"
            base.write_bytes(body)
            os.chmod(base, 0o600)
            apk = APK(str(base))
            certs = apk.get_certificates_der_v2() + apk.get_certificates_der_v3()
            digests = sorted({hashlib.sha256(cert).hexdigest() for cert in certs})
            if (apk.get_package() != "com.tunneldoom.http" or
                    apk.get_androidversion_name() != "4.3.2" or
                    int(apk.get_androidversion_code()) != 432 or digests != [SIGNER]):
                raise ValueError("APK_IDENTITY_OR_CERTIFICATE_MISMATCH")
            result["apk"] = {"package_name": apk.get_package(), "version_name": "4.3.2",
                "version_code": 432, "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body), "certificate_sha256": digests,
                "certificate_matches_prior_authorized_sample": True,
                "apk_signature_cryptographically_verified": False}
            matching = 0
            for raw in apk.get_all_dex():
                if b"ConfigUpdateco" not in raw:
                    continue
                for cls in DEX(raw).get_classes():
                    if cls.get_name() != "Lcom/tunneldoom/http/util/ConfigUpdateco;":
                        continue
                    for method in cls.get_methods():
                        if method.get_name() != "doInBackground" or not method.get_code():
                            continue
                        instructions = list(method.get_code().get_bc().get_instructions())
                        if any(i.get_name().startswith("const-string") and
                               UPDATER in i.get_output() for i in instructions):
                            matching += 1
            if matching != 1:
                raise ValueError("UPDATER_LITERAL_NOT_CONFIRMED")
            result["updater"] = {"literal_confirmed_in_code": True, "method": "GET",
                "matching_code_methods": matching, "no_redirect_followed": True}
            request = Request(UPDATER, headers={"User-Agent": "Dalvik/2.1.0",
                                               "Accept-Encoding": "identity"})
            with build_opener(NoRedirect()).open(request, timeout=30) as response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError("REMOTE_RESPONSE_INVALID")
                encrypted = response.read(8 * 1024 * 1024 + 1)
                result["http_status"] = response.status
            if not encrypted or len(encrypted) > 8 * 1024 * 1024:
                raise ValueError("REMOTE_SIZE_INVALID")
            from decoders.Python.apps.TunnelDOOM_VPN import codec
            decoded = codec.decode_catalog(encrypted)
            from scripts.apk_analysis.tunneldoom_verify import reference
            expected, fields, _ = reference(encrypted)
            if decoded != expected or json.loads(codec.run(encrypted)) != expected:
                raise ValueError("COMPLETE_JCA_PARITY_FAILED")
            result["catalog"] = {"version": decoded["Version"],
                "servers": len(decoded["Servers"]), "encrypted_fields": fields,
                "ciphertext_bytes": len(encrypted),
                "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                "plaintext_json_sha256": hashlib.sha256(codec.run(encrypted).encode()).hexdigest(),
                "complete_json_and_jca_parity": True}
            result["status"] = "VERIFIED_REAL"
    except Exception as error:
        result["status"] = "FAILED"
        result["error_type"] = type(error).__name__
    finally:
        result["dependencies"] = sorted(
            ({"name": d.metadata.get("Name", "UNKNOWN"), "version": d.version}
             for d in importlib.metadata.distributions()), key=lambda d: d["name"].lower())
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, separators=(",", ":")))
    return 0 if result["status"] == "VERIFIED_REAL" else 1

if __name__ == "__main__":
    raise SystemExit(main())
