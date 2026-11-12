#!/usr/bin/env python3
"""Fetch the owner-provided direct URL, keeping its temporary path out of Git.

Run from repository root. Uses the inherited proxy and normal TLS verification.
An APK container candidate is not proof of package identity or a working method.
"""
import argparse
import datetime
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Private text file containing the full URL")
    parser.add_argument("private", type=Path, help="Private response directory")
    parser.add_argument("report", type=Path, help="Sanitized JSON report")
    args = parser.parse_args()
    url = args.source.read_text().strip()
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "download1587.mediafire.com"
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or "/ypaiywpzrvslef1/" not in parsed.path):
        raise ValueError("Expected the exact owner-provided HTTPS MediaFire download host and file key")
    args.private.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = args.private / "response.bin"
    headers = args.private / "headers.txt"
    body.unlink(missing_ok=True)
    command = ["curl", "-sS", "-L", "--fail", "--proto", "=https", "--proto-redir", "=https",
               "--max-time", "120", "--max-filesize", "209715200", "-A", "Mozilla/5.0",
               "-D", str(headers), "-o", str(body), "-w", "%{json}", url]
    result = subprocess.run(command, capture_output=True, text=True)
    metadata = json.loads(result.stdout) if result.stdout else {}
    data = body.read_bytes() if body.exists() else b""
    candidate = False
    zip_error = None
    if result.returncode == 0 and data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(body) as archive:
                candidate = "AndroidManifest.xml" in archive.namelist() and archive.testzip() is None
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            zip_error = type(exc).__name__
    if body.exists():
        body.chmod(0o600)
    if headers.exists():
        headers.chmod(0o600)
    report = {
        "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sourceHost": parsed.hostname,
        "fileKey": "ypaiywpzrvslef1",
        "sourceUrlSha256": hashlib.sha256(url.encode()).hexdigest(),
        "temporaryUrlOmitted": True,
        "curlExit": result.returncode,
        "httpStatus": metadata.get("http_code"),
        "contentType": metadata.get("content_type"),
        "downloadedBytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest() if data else None,
        "htmlUnavailable": b"<title>Site Unavailable</title>" in data,
        "apkContainerCandidate": candidate,
        "zipError": zip_error,
        "status": "PENDING_APK_IDENTITY" if candidate else "PENDING_APK_ACQUISITION",
        "transportError": "curl request failed; inspect private output" if result.returncode else None,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
