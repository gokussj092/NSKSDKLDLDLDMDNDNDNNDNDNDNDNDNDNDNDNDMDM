from __future__ import annotations

from functools import wraps
from typing import Any

from .config import AppConfig
from .utils import thread_options


def is_admin(user_id: Any, config: AppConfig) -> bool:
    if user_id is None or isinstance(user_id, bool):
        return False
    try:
        return int(user_id) in config.admins
    except (TypeError, ValueError):
        return False


def can_use_private_chat(user_id: Any, config: AppConfig) -> bool:
    return is_admin(user_id, config) or (
        type(user_id) is int and user_id in config.allowed_private_users
    )


def is_authorized(message: Any, config: AppConfig) -> bool:
    """Apply independent permissions for group and private decoding."""
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat = getattr(message, "chat", None)
    chat_id = getattr(chat, "id", None)
    chat_type = str(getattr(chat, "type", "") or "").lower()

    if chat_type == "private":
        return can_use_private_chat(user_id, config)
    if chat_type in {"group", "supergroup"}:
        return config.allow_all_groups or chat_id in config.allowed_groups
    return False


def require_authorized(resource: str = "Este contenido"):
    """Protege un handler con la política de acceso única de SP-DECODE."""

    def decorator(handler):
        @wraps(handler)
        def wrapped(message, *args, **kwargs):
            from .runtime import bot, settings

            if not is_authorized(message, settings):
                access_hint = (
                    "El bot acepta cualquier grupo, pero este chat no es un grupo autorizado."
                    if settings.allow_all_groups
                    else "Usa /id para consultar los identificadores y pedir acceso a un administrador."
                )
                bot.reply_to(
                    message,
                    "<b>Acceso no autorizado</b>\n"
                    f"{resource} solo se procesa en grupos o chats privados autorizados.\n"
                    f"{access_hint}",
                    parse_mode="HTML",
                    **thread_options(message),
                )
                return None
            return handler(message, *args, **kwargs)

        wrapped.__spdecode_requires_authorization__ = True
        return wrapped

    return decorator
