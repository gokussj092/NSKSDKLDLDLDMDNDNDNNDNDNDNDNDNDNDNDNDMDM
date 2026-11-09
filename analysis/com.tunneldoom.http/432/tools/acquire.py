#!/usr/bin/env python3
"""Download a candidate TunnelDOOM XAPK; verify package/version before saving.

Does not execute APK code. Manifest metadata is NOT proof of the APK signer.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener
import zipfile
from io import BytesIO

SOURCE = "https://d.apkpure.net/b/XAPK/com.tunneldoom.http?version=latest"
PACKAGE = "com.tunneldoom.http"
EXPECTED_NAME = "4.3.2"
EXPECTED_CODE = 432
MAX_BYTES = 125 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024


class AcquireError(ValueError):
    pass


def vetted_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname
        if (parts.scheme != "https" or parts.port not in (None, 443)
                or not host or (host != "apkpure.net" and
                not host.endswith(".apkpure.net") and
                host != "apkpure.com" and not host.endswith(".apkpure.com") and
                host != "data.winudf.com")
                or parts.username or parts.password or parts.fragment):
            raise AcquireError("UNTRUSTED_DOWNLOAD_URL")
    except ValueError as exc:
        raise AcquireError("UNTRUSTED_DOWNLOAD_URL") from exc
    return url


class SafeRedirects(HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops += 1
        if self.hops > 4:
            raise AcquireError("TOO_MANY_REDIRECTS")
        vetted_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_xapk() -> bytes:
    vetted_url(SOURCE)
    request = Request(SOURCE, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
        "Accept": "application/octet-stream,*/*",
        "Accept-Encoding": "identity",
    })
    with build_opener(SafeRedirects(), HTTPSHandler()).open(request, timeout=45) as resp:
        if resp.status != 200 or resp.headers.get("Content-Encoding", "identity") != "identity":
            raise AcquireError("INVALID_DOWNLOAD_RESPONSE")
        if (resp.headers.get("Content-Length") and
                int(resp.headers["Content-Length"]) > MAX_BYTES):
            raise AcquireError("DOWNLOAD_TOO_LARGE")
        data = resp.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        raise AcquireError("DOWNLOAD_TOO_LARGE")
    return data


def analyze_bytes(data: bytes) -> dict:
    if not data or len(data) > MAX_BYTES:
        raise AcquireError("INVALID_XAPK_SIZE")
    try:
        with zipfile.ZipFile(BytesIO(data)) as xapk:
            names = xapk.namelist()
            if len(names) > 250 or len(names) != len(set(names)):
                raise AcquireError("UNSAFE_XAPK_ENTRIES")
            apks = [name for name in names if name.endswith(".apk") and "/" not in name]
            if not apks:
                raise AcquireError("MISSING_BASE_APK")
            if "manifest.json" not in names:
                raise AcquireError("MANIFEST_UNAVAILABLE")
            entry = xapk.getinfo("manifest.json")
            if entry.file_size > MAX_MANIFEST:
                raise AcquireError("OVERSIZED_MANIFEST")
            obj = json.loads(xapk.read(entry))
            package = obj.get("package_name") or obj.get("packageName")
            name = obj.get("version_name") or obj.get("versionName")
            code = obj.get("version_code") or obj.get("versionCode")
    except (zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcquireError("INVALID_XAPK") from exc
    if package != PACKAGE:
        raise AcquireError("UNEXPECTED_PACKAGE")
    if name != EXPECTED_NAME or str(code) != str(EXPECTED_CODE):
        raise AcquireError("UNEXPECTED_VERSION")
    return {"status": "xapk_manifest_matches_expected_signer_unverified",
            "package": package, "versionName": name, "versionCode": int(code),
            "xapkSha256": hashlib.sha256(data).hexdigest(),
            "xapkBytes": len(data), "archiveApkCount": len(apks)}


def save_private(data: bytes, path: Path) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="Private .xapk output outside the repository")
    args = parser.parse_args(argv)
    try:
        data = fetch_xapk()
        result = analyze_bytes(data)
        save_private(data, args.output)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (AcquireError, OSError, TimeoutError, ValueError):
        print(json.dumps({"status": "error", "code": "ACQUISITION_OR_IDENTITY_FAILED"}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
