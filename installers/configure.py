#!/usr/bin/env python3
from __future__ import annotations

import getpass
import json
import os
import re
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_DIR / "config.json"

DEFAULT_RUNTIME = {
    "downloads_dir": "Downloads",
    "results_dir": "Results",
    "decoder_timeout_seconds": 90,
    "max_file_size_mb": 25,
    "text_session_timeout_seconds": 600,
    "text_session_max_chars": 250000,
}

TOKEN_PATTERN = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{20,}$")


def _load_existing() -> dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        print("WARNING: existing config.json could not be parsed; a new file will be created.")
        return {}
    return data if isinstance(data, dict) else {}


def _parse_ids(raw: str, field_name: str) -> list[int]:
    raw = raw.strip()
    if not raw:
        return []

    values: list[int] = []
    for item in re.split(r"[\s,;]+", raw):
        if not item:
            continue
        try:
            value = int(item)
        except ValueError as exc:
            raise ValueError(f"{field_name}: '{item}' is not a numeric Telegram ID.") from exc
        if value not in values:
            values.append(value)
    return values


def _prompt_ids(label: str, existing: list[int]) -> list[int]:
    default = ",".join(str(item) for item in existing)
    while True:
        suffix = f" [{default}]" if default else " [none]"
        raw = input(f"{label}{suffix}: ").strip()
        if not raw:
            return existing
        if raw.lower() in {"none", "clear", "-"}:
            return []
        try:
            return _parse_ids(raw, label)
        except ValueError as exc:
            print(f"ERROR: {exc}")


def _prompt_token(existing: str) -> str:
    while True:
        prompt = "Telegram bot token"
        if existing:
            prompt += " [press Enter to keep the current token]"
        prompt += ": "

        token = getpass.getpass(prompt).strip()
        if not token and existing:
            return existing
        if not token:
            print("ERROR: a Telegram bot token is required.")
            continue
        if not TOKEN_PATTERN.fullmatch(token):
            print(
                "WARNING: the token format looks unusual. "
                "It will still be saved if you enter it again exactly."
            )
            confirmation = getpass.getpass("Re-enter the token to confirm: ").strip()
            if confirmation != token:
                print("ERROR: tokens did not match.")
                continue
        return token


def _prompt_access_mode(existing_all_groups: bool) -> bool:
    default = "2" if existing_all_groups else "1"
    print()
    print("Group access mode:")
    print("  1) Only selected Telegram groups")
    print("  2) Every group/supergroup where the bot is a member")
    print("     (private chat permissions are configured separately)")
    while True:
        raw = input(f"Choose 1 or 2 [{default}]: ").strip() or default
        if raw == "1":
            return False
        if raw == "2":
            return True
        print("ERROR: choose 1 or 2.")


def main() -> int:
    existing = _load_existing()
    bot_cfg = existing.get("bot", {}) if isinstance(existing.get("bot"), dict) else {}
    access_cfg = (
        existing.get("access", {}) if isinstance(existing.get("access"), dict) else {}
    )
    runtime_cfg = (
        existing.get("runtime", {}) if isinstance(existing.get("runtime"), dict) else {}
    )

    existing_token = str(bot_cfg.get("token", "") or "").strip()
    if existing_token == "PUT_YOUR_TELEGRAM_BOT_TOKEN_HERE":
        existing_token = ""

    defaults = json.loads((PROJECT_DIR / "config.example.json").read_text(encoding="utf-8"))
    legacy_admin = existing.get("chat_privado_especial_id")
    default_admins = defaults["access"]["admins"] if legacy_admin is None else []
    existing_admins = [
        item for item in (access_cfg.get("admins", existing.get("admins", default_admins)) or [])
        if type(item) is int
    ]
    if type(legacy_admin) is int and legacy_admin not in existing_admins:
        existing_admins.append(legacy_admin)
    existing_groups = [
        int(item)
        for item in access_cfg.get("allowed_groups", [])
        if isinstance(item, int) and not isinstance(item, bool)
    ]
    existing_private_users = [
        item for item in (access_cfg.get("allowed_private_users", existing_groups) or [])
        if type(item) is int and item > 0
    ]
    existing_groups = [item for item in existing_groups if item < 0]
    existing_all_groups = bool(access_cfg.get("allow_all_groups", False))

    print("=" * 64)
    print("SP-DECODE INTERACTIVE CONFIGURATION")
    print("=" * 64)
    print("The token is entered without echo and config.json is stored locally.")
    print()

    token = _prompt_token(existing_token)
    admins = _prompt_ids(
        "Administrator user IDs (comma separated)",
        existing_admins,
    )
    allow_all_groups = _prompt_access_mode(existing_all_groups)

    if allow_all_groups:
        allowed_groups: list[int] = []
    else:
        allowed_groups = _prompt_ids(
            "Allowed group IDs (normally negative, comma separated)",
            existing_groups,
        )

    runtime = dict(DEFAULT_RUNTIME)
    runtime.update(
        {
            key: value
            for key, value in runtime_cfg.items()
            if key in DEFAULT_RUNTIME
        }
    )

    config = {
        "bot": {"token": token},
        "access": {
            "admins": admins,
            "allow_all_groups": allow_all_groups,
            "allowed_groups": allowed_groups,
            "allowed_private_users": existing_private_users,
        },
        "runtime": runtime,
    }

    temporary = CONFIG_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(config, indent=4, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, CONFIG_PATH)
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass

    print()
    print(f"Configuration saved to: {CONFIG_PATH}")
    print(f"Administrators: {len(admins)}")
    if allow_all_groups:
        print("Group access: ALL groups/supergroups")
    else:
        print(f"Group access: {len(allowed_groups)} selected group(s)")

    if not admins and not existing_private_users:
        print(
            "WARNING: no administrator IDs were configured. "
            "Private decoding access will not be available."
        )
    if not allow_all_groups and not allowed_groups:
        print(
            "WARNING: no allowed groups were configured. "
            "Decoding in groups will be unavailable until a group is authorized."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
