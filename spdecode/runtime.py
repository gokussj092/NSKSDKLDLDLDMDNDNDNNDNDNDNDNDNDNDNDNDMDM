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
    raise SystemExit(f"Error de configuración: {exc}") from exc

settings.downloads_dir.mkdir(parents=True, exist_ok=True)
settings.results_dir.mkdir(parents=True, exist_ok=True)

bot = telebot.TeleBot(settings.token)

group_mode = "todos" if settings.allow_all_groups else str(len(settings.allowed_groups))
logger.info(
    "Configuración cargada: %d admin(s), grupos=%s.",
    len(settings.admins),
    group_mode,
)



_access_lock = Lock()


def set_chat_permission(identifier: int, allowed: bool) -> bool:
    """Write one permission and publish the new snapshot for the next message."""
    global settings
    if type(identifier) is not int or identifier == 0 or abs(identifier) >= 2**52:
        raise ValueError("ID de Telegram inválido.")

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
