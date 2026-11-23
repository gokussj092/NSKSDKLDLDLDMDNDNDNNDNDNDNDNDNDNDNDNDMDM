"""Short-lived, private Telegram credential prompts for the shared decoders."""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, Timer
from typing import Callable

from telebot.types import ForceReply

from cloud.workers.python.engine import DecodeFailure
from spdecode.access import require_authorized
from spdecode.decoder_runtime import DecodeResult, decode
from spdecode.runtime import bot, settings


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
_PROMPT = "SP-DECODE · Solicitud privada"
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
    marker: object = field(default_factory=object)
    credentials: dict[str, str] = field(default_factory=dict)
    attempts: int = 0
    prompt_id: int | None = None
    busy: bool = False
    timer: Timer | None = None


_pending: dict[tuple[int, int], _Pending] = {}
_lock = Lock()


def _private_session_key(message) -> tuple[int, int] | None:
    chat = getattr(message, "chat", None)
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if getattr(chat, "type", None) == "private" and user_id is not None:
        return chat.id, user_id
    return None


def _remove(key: tuple[int, int] | None, marker: object | None = None) -> bool:
    with _lock:
        pending = _pending.get(key)
        if pending is None or (marker is not None and pending.marker != marker):
            return False
        del _pending[key]
        if pending.timer is not None:
            pending.timer.cancel()
        pending.credentials.clear()
        return True


def cancel_pending_credentials(message) -> bool:
    return _remove(_private_session_key(message))


def _prompt(key, pending, *, invalid=False) -> None:
    with _lock:
        if _pending.get(key) is not pending:
            return
        missing = next(field for field in pending.required if field not in pending.credentials)
        pending.prompt_id = None
    prefix = "Las credenciales no coincidieron. " if invalid else ""
    try:
        reply = bot.send_message(
            key[0],
            f"{_PROMPT}\n{prefix}Responde a este mensaje con {_LABELS[missing]}. "
            "La solicitud caduca en 3 minutos y permite hasta 3 intentos. Usa /cancel para descartarla.",
            reply_markup=ForceReply(),
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
    key = _private_session_key(message)
    if key is None:
        bot.reply_to(message, "Este contenido requiere credenciales. Envíalo al chat privado del bot.")
        return

    pending = _Pending(payload, suffix, deliver, _REQUIRED[code])
    with _lock:
        old = _pending.get(key)
        count = len(_pending) - (old is not None)
        size = len(payload) + sum(len(item.payload) for item in _pending.values() if item is not old)
        if count >= _MAX_PENDING or size > _MAX_PENDING_BYTES:
            accepted = False
        else:
            if old is not None:
                if old.timer is not None:
                    old.timer.cancel()
                old.credentials.clear()
            pending.timer = Timer(_TTL_SECONDS, _remove, args=(key, pending.marker))
            pending.timer.daemon = True
            _pending[key] = pending
            pending.timer.start()
            accepted = True

    if accepted:
        _prompt(key, pending)
    else:
        bot.reply_to(message, "Hay demasiadas solicitudes pendientes. Intenta de nuevo en unos minutos.")


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
            bot.reply_to(message, _ERROR_MESSAGES.get(error.code, "No se pudo decodificar este contenido."))
    else:
        deliver(result)
    return True


def _is_credential_reply(message) -> bool:
    if _private_session_key(message) is None:
        return False
    reply = getattr(message, "reply_to_message", None)
    if reply is None:
        return False
    # Also consume late replies, so expired credential text cannot become input
    # for a generic Telegram text handler.
    return ((getattr(reply, "text", "") or "").startswith(_PROMPT + "\n") and
            getattr(getattr(reply, "from_user", None), "is_bot", False))


@bot.message_handler(func=_is_credential_reply)
@require_authorized("Las credenciales del decodificador")
def handle_credential_reply(message) -> None:
    key = _private_session_key(message)
    value = getattr(message, "text", None) or ""
    with _lock:
        pending = _pending.get(key)
        if pending is None or pending.prompt_id != message.reply_to_message.message_id or pending.busy:
            pending = None
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

    if pending is None:
        bot.reply_to(message, "Esta solicitud ya no está activa o se está procesando.")
        return
    if not valid:
        bot.send_message(key[0], "La credencial está vacía o es demasiado larga.")
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
            bot.send_message(key[0], _ERROR_MESSAGES.get(error.code, "No se pudo abrir el contenido. Envía el original para volver a intentar."))
    else:
        if _remove(key, pending.marker):
            pending.deliver(result)
