#!/usr/bin/env python3
"""Manage public SP-DECODE remote services independently of expiring private QA.

No provider URL, request contents, signing key, or decoded data is printed.
Never creates substitute EHI keys: the real vendor keys are required.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys
import time
from urllib.parse import urlsplit
from urllib.request import urlopen

ROOT = Path(os.environ.get("SPDECODE_HOME", "/opt/spdecode"))
CFG = Path(os.environ.get("SPDECODE_CONFIG_DIR", "/etc/spdecode"))
ENV = CFG / "cloud.env"
COMPOSE = ROOT / "repo/cloud/compose.yaml"
NUR_ASSET = ROOT / "repo/android/app/src/main/assets/nur_tunnel_server_endpoint.json"
QA_STATE = CFG / "qa-previous.json"
CATALOG_BASE = 11
FLAGS = ("CLOUD_EHI_IMPORT_ENABLED", "CLOUD_NUR_FETCH_ENABLED",
         "CLOUD_SERVER_VPN_ENABLED", "CLOUD_NUR_CATALOG_URL",
         "CLOUD_SERVER_VPN_CATALOG_VERSION")


def fail(message: str) -> None:
    raise SystemExit("ERROR: " + message)


def current_lines() -> list[str]:
    if not ENV.is_file() or not COMPOSE.is_file():
        fail("Run the VPS installer and update the source branch first.")
    if ENV.stat().st_mode & 0o077:
        fail("Unsafe cloud.env permissions (expected 0600).")
    return ENV.read_text(encoding="utf-8").splitlines()


def value(lines: list[str], key: str) -> str:
    for entry in lines:
        if entry.startswith(key + "="):
            return entry.split("=", 1)[1].strip().strip("'\"")
    return ""


def ehi_ready(lines: list[str]) -> bool:
    return (len(value(lines, "CLOUD_EHI_SIGN_KEY")) == 32
            and len(value(lines, "CLOUD_EHI_RESPONSE_KEY").encode("utf-8")) == 32)


def validated_nur() -> str:
    """Read the existing private asset but never echo it."""
    try:
        url = json.loads(NUR_ASSET.read_text(encoding="utf-8"))["catalogUrl"]
        parts = urlsplit(url)
    except (OSError, ValueError, KeyError, TypeError):
        fail("Approved NUR source is absent or unreadable.")
    if (not isinstance(url, str) or len(url) > 2048
            or parts.scheme != "https" or parts.netloc != "strongteam.co"
            or parts.hostname != "strongteam.co" or not parts.path.startswith("/")
            or len(parts.path) > 256 or parts.query or parts.fragment
            or parts.username or parts.password or parts.port or
            any(c.isspace() for c in url)):
        fail("NUR URL fails the approved-provider security policy.")
    return url


def catalog_next(lines: list[str]) -> str:
    raw = value(lines, "CLOUD_SERVER_VPN_CATALOG_VERSION") or str(CATALOG_BASE)
    if not re.fullmatch(r"[0-9]{1,9}", raw):
        fail("Invalid Server VPN catalog version.")
    previous = int(raw)
    if previous < CATALOG_BASE or previous >= 999_999_999:
        fail("Cannot increment Server VPN catalog version.")
    return str(previous + 1)


def rewrite(lines: list[str], updates: dict[str, str]) -> list[str]:
    return ([entry for entry in lines if entry.split("=", 1)[0] not in updates]
            + [key + "=" + val for key, val in updates.items()])


def atomic(lines: list[str]) -> None:
    temp = ENV.with_name(".cloud.env.provider-tmp")
    if temp.exists():
        fail("Temporary environment update already exists; inspect before retrying.")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, ENV)
        os.chmod(ENV, 0o600)
    finally:
        temp.unlink(missing_ok=True)


def compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "--project-name", "spdecode",
         "--env-file", str(ENV), "-f", str(COMPOSE), *args],
        check=True, stdout=subprocess.DEVNULL,
    )


def healthy() -> bool:
    for _ in range(15):
        try:
            with urlopen("http://127.0.0.1:3000/api/v1/ready", timeout=4) as response:
                if response.status == 200:
                    return True
        except (OSError, ValueError):
            pass
        time.sleep(2)
    return False


def status(lines: list[str]) -> None:
    print("API:", "ENABLED" if value(lines, "CLOUD_API_ENABLED") == "true" else "DISABLED")
    print("Proveedores de Servidores VPN:",
          "ENABLED" if value(lines, "CLOUD_SERVER_VPN_ENABLED") == "true" else "DISABLED")
    nur = value(lines, "CLOUD_NUR_FETCH_ENABLED") == "true" and bool(value(lines, "CLOUD_NUR_CATALOG_URL"))
    print("Servidores VPN (catálogo):", "ENABLED" if nur else "DISABLED")
    ehi = value(lines, "CLOUD_EHI_IMPORT_ENABLED") == "true" and ehi_ready(lines)
    print("HTTP Injector Cloud:", "ENABLED" if ehi else "NOT CONFIGURED")
    if not ehi_ready(lines):
        print("HTTP Injector requires genuine existing server-side 32-byte sign and response keys.")
    print("Server VPN catalog version:",
          value(lines, "CLOUD_SERVER_VPN_CATALOG_VERSION") or str(CATALOG_BASE))
    print("Private QA:",
          "ENABLED" if value(lines, "CLOUD_QA_ENABLED") == "true" else "DISABLED")
    print("No URL or credential values printed.")


def apply(action: str, previous: list[str]) -> None:
    if QA_STATE.exists() or value(previous, "CLOUD_QA_ENABLED") == "true":
        fail("Stop the private QA session first; preserve its state with 'spdecode qa stop'.")
    if value(previous, "CLOUD_API_ENABLED") != "true":
        fail("Cloud API is not enabled; do not change provider settings.")
    if action == "enable":
        changes = {
            "CLOUD_SERVER_VPN_ENABLED": "true",
            "CLOUD_NUR_FETCH_ENABLED": "true",
            "CLOUD_NUR_CATALOG_URL": validated_nur(),
            "CLOUD_EHI_IMPORT_ENABLED": "true" if ehi_ready(previous) else "false",
        }
    else:
        changes = {
            "CLOUD_SERVER_VPN_ENABLED": "false",
            "CLOUD_NUR_FETCH_ENABLED": "false",
            "CLOUD_EHI_IMPORT_ENABLED": "false",
        }
    if any(value(previous, k) != v for k, v in changes.items()):
        changes["CLOUD_SERVER_VPN_CATALOG_VERSION"] = catalog_next(previous)
    if not any(value(previous, k) != v for k, v in changes.items()):
        print("No changes necessary.")
        status(previous)
        return
    atomic(rewrite(previous, changes))
    try:
        compose("up", "-d", "--no-deps", "--force-recreate", "web")
        if not healthy():
            raise RuntimeError("API readiness check failed after update.")
    except Exception as exc:
        atomic(previous)
        try:
            compose("up", "-d", "--no-deps", "--force-recreate", "web")
        except Exception:
            print("WARNING: web service rollback needs manual inspection.", file=sys.stderr)
        fail("Provider changes rolled back after failed health check: " + type(exc).__name__)
    print("Remote service flags applied persistently (separate from QA).")
    status(rewrite(previous, changes))



def import_ehi_script(filename: str, previous: list[str]) -> None:
    """Install only the vendor method's two fixed keys without executing the script.

    User supplies HTTPINJECTOR_CLOUD.py privately on the VPS with chmod 0600.
    Never copy source/keys to Git or print sensitive method material.
    """
    if QA_STATE.exists() or value(previous, "CLOUD_QA_ENABLED") == "true":
        fail("Stop the private QA session before configuring HTTP Injector Cloud.")
    if value(previous, "CLOUD_API_ENABLED") != "true":
        fail("Cloud API is disabled. Enable it and restart web before importing EHI.")
    script = Path(filename)
    try:
        mode = script.lstat()
        if not stat.S_ISREG(mode.st_mode) or mode.st_uid != 0 or mode.st_mode & 0o077:
            fail("Method script must be a root-owned regular file with mode 0600.")
        if mode.st_size < 100 or mode.st_size > 64 * 1024:
            fail("Unexpected method script size.")
        with script.open("r", encoding="utf-8") as stream:
            program = ast.parse(stream.read(), filename="<private-method>")
    except (OSError, UnicodeError, SyntaxError):
        fail("Cannot read the private HTTP Injector Cloud method.")
    names = {}
    for node in program.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        identifier = node.targets[0].id
        if identifier not in ("SIGN_SECRET", "API_KEY", "APP_BUILD", "ENDPOINT"):
            continue
        try:
            names[identifier] = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError, RecursionError):
            fail("Unexpected HTTP Injector method constant type.")
    sign = names.get("SIGN_SECRET")
    key = names.get("API_KEY")
    if (names.get("APP_BUILD") != "244" or
        names.get("ENDPOINT") != "https://www.ehi.tools/httpinjector/import_config" or
        not isinstance(sign, str) or not sign.isascii() or len(sign) != 32 or
        not isinstance(key, bytes) or len(key) != 32 or not key.isascii()):
        fail("HTTP Injector method is incompatible with the current 6.5.0/244 adapter.")
    response = key.decode("ascii")
    # Only the private cloud.env stores these fixed app-protocol values.
    # The worker and the Android APK never receive them.
    changes = {
        "CLOUD_EHI_SIGN_KEY": sign,
        "CLOUD_EHI_RESPONSE_KEY": response,
        "CLOUD_EHI_IMPORT_ENABLED": "true",
    }
    if all(value(previous, k) == v for k, v in changes.items()):
        print("HTTP Injector Cloud is already configured.")
        return
    atomic(rewrite(previous, changes))
    try:
        compose("up", "-d", "--no-deps", "--force-recreate", "web")
        if not healthy():
            raise RuntimeError("Health check failed.")
    except Exception as exc:
        atomic(previous)
        try:
            compose("up", "-d", "--no-deps", "--force-recreate", "web")
        except Exception:
            print("WARNING: web rollback needs manual verification.", file=sys.stderr)
        fail("HTTP Injector credentials were rolled back: " + type(exc).__name__)
    print("HTTP Injector Cloud method 6.5.0/244 provisioned; credentials not printed.")
    status(rewrite(previous, changes))


def main() -> None:
    if os.geteuid() != 0:
        fail("Use sudo spdecode providers status|enable|disable.")
    if len(sys.argv) == 3 and sys.argv[1] == "import-ehi":
        import_ehi_script(sys.argv[2], current_lines())
        return
    if len(sys.argv) != 2 or sys.argv[1] not in ("status", "enable", "disable"):
        fail("Usage: spdecode providers status|enable|disable|import-ehi /root/HTTPINJECTOR_CLOUD.py")
    lines = current_lines()
    if sys.argv[1] == "status":
        status(lines)
    else:
        apply(sys.argv[1], lines)


if __name__ == "__main__":
    main()
