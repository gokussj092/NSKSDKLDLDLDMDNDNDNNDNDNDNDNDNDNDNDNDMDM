#!/usr/bin/env python3
"""Decoder for .ovpn files imported by ExoticFast VIP.

The app imports .ovpn profiles in OpenVPNClient.onActivityResult (requestCode 2):
the path must end with ".ovpn" and the file is parsed by b2.C0376n
(ics-openvpn's VpnProfile parser, c4.f). A .ovpn profile is plain text:
directives plus inline <ca>/<cert>/<key>/<tls-auth>/<tls-crypt> blocks.

This script parses a .ovpn file into the fields SP-DECODE shows
(remote hosts/ports, proto, dev, cipher, auth, user/pass flag, embedded
certificates/keys) as JSON. Usage:

    python3 ovpn_decoder.py profile.ovpn [--json out.json]
"""
import argparse
import json
import re
import sys

INLINE_BLOCKS = ("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2",
                 "crl-verify", "auth-user-pass", "static", "pkcs12")
MULTI = {"remote", "remote-cert-tls", "route", "route-ipv6", "push",
         "dhcp-option", "tls-cipher", "setenv", "plugin", "auth-user-pass"}


def parse_ovpn(text: str) -> dict:
    out = {"directives": {}, "inline": {}, "remotes": []}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        m = re.match(r"^<(\S+)>$", line)
        if m:
            name = m.group(1)
            buf = []
            while i < len(lines):
                inner = lines[i].strip()
                i += 1
                if inner == f"</{name}>":
                    break
                buf.append(lines[i - 1].rstrip("\n"))
            out["inline"][name] = "\n".join(buf)
            continue
        if line.startswith("</"):
            continue
        parts = line.split(None, 1)
        key = parts[0]
        value = parts[1] if len(parts) > 1 else ""
        if key == "remote":
            fields = value.split()
            rem = {"host": fields[0] if fields else ""}
            if len(fields) > 1:
                rem["port"] = fields[1]
            if len(fields) > 2:
                rem["proto"] = fields[2]
            out["remotes"].append(rem)
            out["directives"].setdefault("remote", []).append(value)
        elif key in MULTI:
            out["directives"].setdefault(key, []).append(value)
        else:
            out["directives"][key] = value
    return out


def summarize(parsed: dict) -> dict:
    d = parsed["directives"]
    return {
        "remotes": parsed["remotes"],
        "proto": d.get("proto"),
        "dev": d.get("dev"),
        "cipher": d.get("cipher"),
        "auth": d.get("auth"),
        "auth_user_pass": "auth-user-pass" in d,
        "inline_blocks": sorted(parsed["inline"].keys()),
        "has_ca": "ca" in parsed["inline"],
        "has_cert": "cert" in parsed["inline"],
        "has_key": "key" in parsed["inline"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Decode an .ovpn profile (ExoticFast VIP)")
    ap.add_argument("file", help=".ovpn profile to parse")
    ap.add_argument("--json", help="write full parsed JSON here")
    args = ap.parse_args()
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    parsed = parse_ovpn(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(parsed, fh, ensure_ascii=False, indent=2)
        print(f"wrote {args.json}")
    print(json.dumps(summarize(parsed), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
