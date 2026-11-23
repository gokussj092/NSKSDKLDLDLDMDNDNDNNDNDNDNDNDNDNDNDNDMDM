"""Short-lived Telegram credential prompts tied to the original message."""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, Timer
from typing import Callable

from telebot.types import ForceReply

from cloud.workers.python.engine import DecodeFailure
from spdecode.access import is_authorized, require_authorized
from spdecode.decoder_runtime import DecodeResult, decode
from spdecode.runtime import bot, settings
from spdecode.utils import thread_options


_REQUIRED = {
    "PASSWORD_REQUIRED": ("password",),
    "HWID_REQUIRED": ("hwid",),
    "HWID_PASSWORD_REQUIRED": ("hwid", "password"),
}
_LABELS = {"password": "la contraseña del archivo o enlace", "hwid": "el HWID del archivo"}
_ERROR_MESSAGES = {
    "AUTH_FAILED": "Las credenciales no coinciden o el contenido no superó la verificación.",
    "INVALID_CREDENTIALS": "Las credenciales no tienen un formato válido.",
    "PRIVATE_KEY_REQUIRED": "Este perfil necesita una clave privada. Usa SP-DECODE en el dispositivo que tiene esa clave.",
    "RECIPIENT_MISMATCH": "El perfil está protegido para otro destinatario.",
    "NPVS_PROTECTION_UNSUPPORTED": "Esta variante de protección NPV Tunnel no es compatible.",
    "UNSUPPORTED_VERSION": "Esta versión del formato no es compatible.",
    "UNSUPPORTED_METHOD": "Este método del formato no es compatible.",
    "UNSUPPORTED_VARIANT": "Esta variante del formato no es compatible.",
    "INPUT_TOO_LARGE": "El contenido supera el límite de procesamiento.",
    "OUTPUT_TOO_LARGE": "El resultado supera el límite de entrega.",
    "ENGINE_TIMEOUT": "El decodificador superó el tiempo permitido.",
    "ENGINE_UNAVAILABLE": "El decodificador no está disponible en este momento.",
}
_PROMPT = "SP-DECODE · Credencial pendiente"
_TTL_SECONDS = 180
_MAX_ATTEMPTS = 3
_MAX_PENDING = 16
_MAX_PENDING_BYTES = 32 * 1024 * 1024


@dataclass(slots=True)
class _Pending:
    payload: bytes
    suffix: str | None
    deliver: Callable[[DecodeResult], None]
    required: tuple[str, ...]
    original: object
    marker: object = field(default_factory=object)
    credentials: dict[str, str] = field(default_factory=dict)
    attempts: int = 0
    prompt_id: int | None = None
    busy: bool = False
    timer: Timer | None = None


_Actor = tuple[int, int | None, int]
_SessionKey = tuple[_Actor, int]
_pending: dict[_SessionKey, _Pending] = {}
_lock = Lock()


def _actor(message) -> _Actor | None:
    chat = getattr(message, "chat", None)
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if (getattr(chat, "type", None) not in {"private", "group", "supergroup"} or
            user_id is None or getattr(message, "sender_chat", None) is not None):
        return None
    return chat.id, getattr(message, "message_thread_id", None), user_id


def _remove(key: _SessionKey, marker: object | None = None) -> bool:
    with _lock:
        pending = _pending.get(key)
        if pending is None or (marker is not None and pending.marker != marker):
            return False
        del _pending[key]
        if pending.timer is not None:
            pending.timer.cancel()
        pending.credentials.clear()
        return True


def _find_reply(actor: _Actor, reply_id: int) -> tuple[_SessionKey, _Pending] | None:
    # Called under _lock. Telegram message IDs are local to each chat.
    return next(
        ((key, pending) for key, pending in _pending.items()
         if key[0] == actor and reply_id in (key[1], pending.prompt_id)),
        None,
    )


def cancel_pending_credentials(message) -> bool:
    actor = _actor(message)
    if actor is None:
        return False
    reply = getattr(message, "reply_to_message", None)
    with _lock:
        if reply is None:
            targets = [(key, pending.marker) for key, pending in _pending.items() if key[0] == actor]
        else:
            target = _find_reply(actor, reply.message_id)
            targets = [(target[0], target[1].marker)] if target is not None else []
    removed = [_remove(key, marker) for key, marker in targets]
    return any(removed)


def _reply(message, text: str, **kwargs):
    return bot.reply_to(message, text, **thread_options(message), **kwargs)


def _prompt(key: _SessionKey, pending: _Pending, *, invalid=False) -> None:
    with _lock:
        if _pending.get(key) is not pending:
            return
        missing = next(field for field in pending.required if field not in pending.credentials)
        pending.prompt_id = None
    prefix = "Las credenciales no coincidieron. " if invalid else ""
    try:
        reply = _reply(
            pending.original,
            f"{_PROMPT}\n{prefix}Responde aquí con {_LABELS[missing]}. "
            "La solicitud caduca en 3 minutos y permite hasta 3 intentos. Usa /cancel para descartarla.",
            reply_markup=ForceReply(selective=True),
        )
    except Exception:
        _remove(key, pending.marker)
        raise
    with _lock:
        if _pending.get(key) is pending:
            pending.prompt_id = reply.message_id
            pending.busy = False


def _begin_prompt(
    message, payload: bytes, suffix: str | None, deliver: Callable[[DecodeResult], None], code: str,
) -> None:
    actor = _actor(message)
    if actor is None:
        _reply(message, "Envía el contenido desde tu cuenta de Telegram para poder responder a la solicitud.")
        return

    key = (actor, message.message_id)
    pending = _Pending(payload, suffix, deliver, _REQUIRED[code], message, busy=True)
    with _lock:
        old = _pending.get(key)
        count = len(_pending) - (old is not None)
        size = len(payload) + sum(len(item.payload) for item in _pending.values() if item is not old)
        accepted = count < _MAX_PENDING and size <= _MAX_PENDING_BYTES
        if accepted:
            if old is not None:
                if old.timer is not None:
                    old.timer.cancel()
                old.credentials.clear()
            pending.timer = Timer(_TTL_SECONDS, _remove, args=(key, pending.marker))
            pending.timer.daemon = True
            _pending[key] = pending
            pending.timer.start()

    if accepted:
        _prompt(key, pending)
    else:
        _reply(message, "Hay demasiadas solicitudes pendientes. Intenta de nuevo en unos minutos.")


def decode_and_reply(
    message, payload: bytes, *, suffix: str | None, deliver: Callable[[DecodeResult], None],
    legacy_text_fallback: bool = False,
) -> bool:
    """Return false only when an existing Telegram text handler can continue."""
    try:
        result = decode(payload, suffix=suffix, timeout_seconds=settings.decoder_timeout_seconds)
    except DecodeFailure as error:
        if error.code in _REQUIRED:
            _begin_prompt(message, payload, suffix, deliver, error.code)
        elif legacy_text_fallback and error.code == "DECODE_FAILED":
            return False
        else:
            _reply(message, _ERROR_MESSAGES.get(error.code, "No se pudo decodificar este contenido."))
    else:
        deliver(result)
    return True


def _is_credential_reply(message) -> bool:
    actor = _actor(message)
    reply = getattr(message, "reply_to_message", None)
    text = getattr(message, "text", None)
    if actor is None or reply is None or not isinstance(text, str):
        return False
    command = text.split(None, 1)[0].split("@", 1)[0].lower() if text.strip() else ""
    if command in {"/cancel", "/cancelar"}:
        return False
    with _lock:
        if _find_reply(actor, reply.message_id) is not None:
            return True
    # Late or foreign replies to a bot prompt must bypass generic text handlers.
    return ((getattr(reply, "text", "") or "").startswith(_PROMPT + "\n") and
            getattr(getattr(reply, "from_user", None), "is_bot", False))


@bot.message_handler(func=_is_credential_reply)
@require_authorized("Las credenciales del decodificador")
def handle_credential_reply(message) -> None:
    actor = _actor(message)
    value = getattr(message, "text", None) or ""
    with _lock:
        target = _find_reply(actor, message.reply_to_message.message_id) if actor is not None else None
        if target is not None:
            key, pending = target
            if pending.busy:
                target = None
            else:
                missing = next(field for field in pending.required if field not in pending.credentials)
                valid = bool(value) and len(value.encode("utf-8")) <= (128 if missing == "hwid" else 4096)
                if valid:
                    pending.credentials[missing] = value
                    pending.busy = True
                    more = any(field not in pending.credentials for field in pending.required)
                    if not more:
                        pending.attempts += 1
                        credentials = pending.credentials.copy()

    if target is None:
        reply = message.reply_to_message
        if reply.chat.id == message.chat.id and thread_options(reply) == thread_options(message):
            _reply(reply, "Esta solicitud ya no está activa o se está procesando.")
        return
    if not valid:
        _reply(pending.original, "La credencial está vacía o es demasiado larga.")
        return
    if more:
        _prompt(key, pending)
        return

    try:
        result = decode(pending.payload, suffix=pending.suffix,
                        timeout_seconds=settings.decoder_timeout_seconds, credentials=credentials)
    except DecodeFailure as error:
        required = _REQUIRED.get(error.code)
        with _lock:
            active = _pending.get(key) is pending
            retry = active and pending.attempts < _MAX_ATTEMPTS and (
                required is not None or error.code in {"AUTH_FAILED", "INVALID_CREDENTIALS"}
            )
            if retry:
                if required and any(field not in pending.credentials for field in required):
                    pending.required = tuple(dict.fromkeys((*pending.required, *required)))
                    pending.attempts -= 1
                else:
                    pending.credentials.clear()
        if retry:
            _prompt(key, pending, invalid=required is None)
        elif active and _remove(key, pending.marker):
            _reply(pending.original, _ERROR_MESSAGES.get(error.code, "No se pudo abrir el contenido. Envía el original para volver a intentar."))
    else:
        from spdecode.runtime import settings as current_settings

        if _remove(key, pending.marker) and is_authorized(message, current_settings):
            pending.deliver(result)
