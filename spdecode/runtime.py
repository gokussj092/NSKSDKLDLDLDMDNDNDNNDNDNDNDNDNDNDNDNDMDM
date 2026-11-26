from __future__ import annotations

import logging
from dataclasses import replace
from threading import Lock

import telebot

from .config import load_config, save_chat_permissions

logger = logging.getLogger("sp-decode")

try:
    settings = load_config()
except Exception as exc:
    raise SystemExit(f"Configuration error: {exc}") from exc

settings.downloads_dir.mkdir(parents=True, exist_ok=True)
settings.results_dir.mkdir(parents=True, exist_ok=True)

bot = telebot.TeleBot(settings.token)

group_mode = "all" if settings.allow_all_groups else str(len(settings.allowed_groups))
logger.info(
    "Configuration loaded: %d admin(s), groups=%s.",
    len(settings.admins),
    group_mode,
)



_access_lock = Lock()


def set_chat_permission(identifier: int, allowed: bool) -> bool:
    """Write one permission and publish the new snapshot for the next message."""
    global settings
    if type(identifier) is not int or identifier == 0 or abs(identifier) >= 2**52:
        raise ValueError("Invalid Telegram ID.")

    field = "allowed_groups" if identifier < 0 else "allowed_private_users"
    with _access_lock:
        previous = getattr(settings, field)
        updated = previous | {identifier} if allowed else previous - {identifier}
        if updated == previous:
            return False
        current = replace(settings, **{field: updated})
        save_chat_permissions(current)
        settings = current
        return True


def restrict_groups() -> bool:
    """Enable the group allowlist and persist it before publishing the new policy."""
    global settings
    with _access_lock:
        if not settings.allow_all_groups:
            return False
        current = replace(settings, allow_all_groups=False)
        save_chat_permissions(current)
        settings = current
        return True


def allow_all_groups() -> bool:
    """Disable the group allowlist and persist it before publishing the new policy."""
    global settings
    with _access_lock:
        if settings.allow_all_groups:
            return False
        current = replace(settings, allow_all_groups=True)
        save_chat_permissions(current)
        settings = current
        return True


def record_known_group(chat_id: int, title: str | None) -> bool:
    """Remember a group the bot is in; persist only when it is new or renamed."""
    global settings
    if type(chat_id) is not int or chat_id >= 0 or abs(chat_id) >= 2**52:
        return False
    clean_title = " ".join(str(title or "").split())
    with _access_lock:
        if settings.known_groups.get(chat_id) == clean_title:
            return False
        updated = dict(settings.known_groups)
        updated[chat_id] = clean_title
        current = replace(settings, known_groups=updated)
        save_chat_permissions(current)
        settings = current
        return True
