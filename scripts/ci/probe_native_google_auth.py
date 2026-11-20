#!/usr/bin/env python3
"""Non-sensitive public health probe for Android Google sign-in."""
from __future__ import annotations

import json
import re
import sys
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPRedirectHandler

ORIGIN = "https://spdecode.xyz"
MAX_BYTES = 8192


def validate_config(status: int, body: dict) -> None:
    if status != 200:
        raise ValueError("NATIVE_CONFIG_HTTP_" + str(status))
    if body.get("enabled") is not True:
        raise ValueError("NATIVE_AUTH_DISABLED_ON_SERVER")
    client_id = body.get("googleWebClientId")
    if not isinstance(client_id, str) or not re.fullmatch(
        r"[0-9]+-[a-z0-9_-]{8,}\.apps\.googleusercontent\.com", client_id
    ):
        raise ValueError("GOOGLE_WEB_CLIENT_ID_UNAVAILABLE")


def validate_account(status: int, body: dict) -> None:
    if status != 200:
        raise ValueError("ACCOUNT_ENDPOINT_HTTP_" + str(status))
    if body.get("authEnabled") is not True:
        raise ValueError("NATIVE_AUTH_DISABLED_ON_SERVER")
    if body.get("user") is not None:
        raise ValueError("ANONYMOUS_ACCOUNT_LEAK")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError("UNEXPECTED_HTTP_REDIRECT")


def get_json(path: str) -> tuple[int, dict]:
    opener = build_opener(NoRedirect)
    request = Request(ORIGIN + path, headers={
        "Accept": "application/json",
        "Cache-Control": "no-store",
        "User-Agent": "SP-DECODE-CI-NativeAuthProbe/1",
    })
    try:
        with opener.open(request, timeout=12) as response:
            raw = response.read(MAX_BYTES + 1)
            status = response.status
    except HTTPError as error:
        # Never print a response body, OAuth token or provider data.
        raise ValueError("HTTP_" + str(error.code) + "_PUBLIC_AUTH") from None
    if len(raw) > MAX_BYTES:
        raise ValueError("RESPONSE_TOO_LARGE")
    body = json.loads(raw.decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError("INVALID_RESPONSE")
    return status, body


def main() -> int:
    try:
        validate_config(*get_json("/api/auth/native-config"))
        print("PASS native-config: enabled and public Web Client ID shape valid (value withheld)")
        validate_account(*get_json("/api/account"))
        print("PASS account: anonymous session has no user, auth service responding")
        print("NOTE: Play signing SHA-1 registration and ID token exchange still require a real device")
        return 0
    except (ValueError, OSError, TimeoutError, json.JSONDecodeError) as error:
        reason = str(error)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,100}", reason):
            reason = "NATIVE_AUTH_NETWORK_OR_RESPONSE_FAILURE"
        print("FAIL Google native public probe: " + reason, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
