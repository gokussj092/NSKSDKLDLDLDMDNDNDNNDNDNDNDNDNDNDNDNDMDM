#!/usr/bin/env python3
"""Rotate the single C6 admin account; print credentials only after real HTTPS login."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

ROOT = Path(os.environ.get("SPDECODE_HOME", "/opt/spdecode"))
CFG = Path(os.environ.get("SPDECODE_CONFIG_DIR", "/etc/spdecode"))
ENV = CFG / "cloud.env"
REPO = ROOT / "repo"
NGINX = Path("/etc/nginx/sites-available/spdecode.conf")

class ResetError(Exception):
    pass

def invoke(args: list[str], *, input_text: str | None = None) -> str:
    # input_text is delivered through stdin, never a process argument or environment.
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ResetError(f"Command failed ({args[0]}), exit {result.returncode}")
    return result.stdout.strip()

def atomic_write(path: Path, data: bytes, mode: int) -> None:
    fd, name = tempfile.mkstemp(prefix=".spdecode-reset-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(name):
            os.unlink(name)

def replace_env(original: bytes, changes: dict[str, str]) -> bytes:
    # Preserve unrelated environment settings and provider keys.
    lines = original.decode("utf-8").splitlines()
    kept = [line for line in lines if not (
        line.split("=", 1)[0] in changes and "=" in line and not line.lstrip().startswith("#")
    )]
    kept.extend(f"{key}={value}" for key, value in changes.items())
    return ("\n".join(kept) + "\n").encode("utf-8")

def fresh_account() -> tuple[str, str, str, str]:
    username = "admin_" + secrets.token_hex(6)
    password = secrets.token_urlsafe(36)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8,
                            p=1, dklen=64, maxmem=32 * 1024 * 1024)
    password_hash = f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"
    signing_key = secrets.token_hex(32)
    return username, password, password_hash, signing_key

def compose(*args: str) -> str:
    return invoke(["docker", "compose", "--project-name", "spdecode",
                   "--env-file", str(ENV), "-f", str(REPO / "cloud/compose.yaml"), *args])

def https_status(panel: str, path: str, *, body: dict | None = None,
                 cookies: Path | None = None, save_cookies: bool = False) -> str:
    cmd = ["curl", "--noproxy", "*", "--proxy", "", "--silent", "--show-error",
           "--connect-timeout", "3", "--max-time", "15",
           "--resolve", f"{panel}:443:127.0.0.1",
           "-o", "/dev/null", "-w", "%{http_code}"]
    if cookies is not None:
        cmd.extend(["--cookie-jar" if save_cookies else "--cookie", str(cookies)])
    input_text = None
    if body is not None:
        cmd.extend(["-X", "POST", "-H", f"Origin: https://{panel}",
                    "-H", "Content-Type: application/json",
                    "-H", "X-SPDecode-Admin-Action: 1", "--data-binary", "@-"])
        input_text = json.dumps(body, separators=(",", ":"))
    return invoke([*cmd, f"https://{panel}{path}"], input_text=input_text)

def validate_login(panel: str, username: str, password: str) -> None:
    # A 401 for guests is not an authentication test. Require 200 for a signed-in
    # session using the exact credentials just written into Docker Compose.
    with tempfile.TemporaryDirectory(prefix="spdecode-login-") as directory:
        jar = Path(directory) / "cookies"
        if https_status(panel, "/admin/login") != "200":
            raise ResetError("Public login page is not reachable over local Nginx HTTPS")
        if https_status(panel, "/api/admin/session") != "401":
            raise ResetError("Guest session did not return HTTP 401")
        actual = https_status(panel, "/api/admin/login",
                              body={"username": username, "password": password},
                              cookies=jar, save_cookies=True)
        if actual != "200":
            raise ResetError(f"Generated login rejected by server (HTTP {actual})")
        if https_status(panel, "/api/admin/session", cookies=jar) != "200":
            raise ResetError("Login returned success but the authenticated session is invalid")

def check_backend() -> None:
    compose("exec", "-T", "web", "node", "--input-type=module", "-e",
            'import {adminSettings} from "./lib/c6-admin-auth.mjs";'
            'process.exit(adminSettings().enabled?0:1)')

def reset_admin() -> None:
    if os.geteuid() != 0:
        raise ResetError("Run with sudo/root")
    if not ENV.is_file() or not (REPO / "cloud/compose.yaml").is_file():
        raise ResetError("SP-DECODE VPS installation not found")
    if not NGINX.is_file():
        raise ResetError("SP-DECODE Nginx configuration not found")
    if ENV.stat().st_mode & 0o077:
        raise ResetError("Unsafe cloud.env permissions; expected chmod 600")
    domain = (CFG / "domain").read_text().strip()
    api_domain = (CFG / "api-domain").read_text().strip()
    panel = (CFG / "panel-domain").read_text().strip()
    generator = REPO / "cloud/infra/vps/nginx-config.py"
    old_env, old_nginx = ENV.read_bytes(), NGINX.read_bytes()
    had_www = bool(re.search(r"server_name\s+www\." + re.escape(domain) + r";", old_nginx.decode("utf-8")))
    nginx_args = ["python3", str(generator), domain, "--api-domain", api_domain,
                  "--panel-domain", panel]
    if had_www:
        nginx_args.append("--www")
    fresh_nginx = invoke(nginx_args).encode("utf-8")
    username, password, password_hash, signing_key = fresh_account()
    fresh_env = replace_env(old_env, {
        "CLOUD_ADMIN_ENABLED": "true",
        "CLOUD_TRUST_PROXY": "true",
        "CLOUD_ADMIN_USERNAME": username,
        "CLOUD_ADMIN_PASSWORD_SCRYPT": f"'{password_hash}'",
        "CLOUD_ADMIN_SESSION_KEY": signing_key,
        "CLOUD_ADMIN_PUBLIC_ORIGIN": f"https://{panel}",
    })
    env_changed = nginx_changed = False
    try:
        # Credentials never enter argv, shell history, Git, Docker build args or logs.
        atomic_write(ENV, fresh_env, 0o600)
        env_changed = True
        atomic_write(NGINX, fresh_nginx, 0o644)
        nginx_changed = True
        invoke(["nginx", "-t"])
        invoke(["systemctl", "reload", "nginx"])
        compose("up", "-d", "--no-deps", "--force-recreate", "web")
        for attempt in range(20):
            try:
                if invoke(["curl", "--noproxy", "*", "--proxy", "",
                           "--silent", "--show-error", "--max-time", "3", "-o", "/dev/null",
                           "-w", "%{http_code}", "http://127.0.0.1:3000/api/v1/health"]) == "200":
                    break
            except ResetError:
                pass
            time.sleep(3)
        else:
            raise ResetError("Next.js did not become healthy")
        check_backend()
        # Admin-only login throttle might still hold previous failed attempts.
        compose("exec", "-T", "redis", "redis-cli", "DEL", "spc6:admin:login:global")
        validate_login(panel, username, password)
    except Exception:
        # Never display unusable credentials. Restore previous configuration.
        if env_changed:
            atomic_write(ENV, old_env, 0o600)
        if nginx_changed:
            atomic_write(NGINX, old_nginx, 0o644)
            try:
                invoke(["nginx", "-t"])
                invoke(["systemctl", "reload", "nginx"])
            except ResetError:
                print("WARNING: Nginx rollback needs manual inspection", file=sys.stderr)
        if env_changed:
            try:
                compose("up", "-d", "--no-deps", "--force-recreate", "web")
            except ResetError:
                print("WARNING: web rollback needs manual inspection", file=sys.stderr)
        raise
    # The former account's username, scrypt hash and signing key are overwritten.
    # Redis sessions signed with the old key cannot authenticate.
    print("\nADMINISTRADOR RESTABLECIDO — LOGIN HTTPS VALIDADO")
    print(f"URL: https://{panel}/admin/login")
    print(f"USUARIO: {username}")
    print(f"CONTRASEÑA: {password}")
    print("La contraseña se muestra UNA SOLA VEZ. Guárdala en un gestor de contraseñas.")
    print("La cuenta anterior y sus sesiones quedaron invalidadas.")

if __name__ == "__main__":
    try:
        reset_admin()
    except (ResetError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"ERROR: Admin reset failed: {exc}", file=sys.stderr)
        sys.exit(1)
