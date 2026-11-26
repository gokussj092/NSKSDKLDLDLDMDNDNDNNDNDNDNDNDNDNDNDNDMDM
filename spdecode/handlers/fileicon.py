"""Attach a thumbnail image to a file: the /fileicon flow.

The user sends /fileicon, then the file, then the thumbnail image. The bot
re-uploads the file bytes with the thumbnail and the SP-DECODE caption
(Design 2). The bytes must be re-uploaded: Telegram ignores the thumbnail
when a document is re-sent by file_id (the thumbnail is bound to the file's
server-side record), so a file_id resend shows the generic document icon.
"""
from __future__ import annotations

import html
import io
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock, Timer
from zoneinfo import ZoneInfo

from PIL import Image, ImageOps

from spdecode.access import require_authorized
from spdecode.runtime import bot, settings
from spdecode.utils import clean_filename, thread_options

logger = logging.getLogger("sp-decode")

_TTL_SECONDS = 180
_MAX_PENDING = 16
_THUMB_MAX_PX = 320
_THUMB_MAX_BYTES = 200 * 1024
# The Bot API only lets a bot download files up to 20 MB, so a bigger file
# cannot be re-uploaded with a thumbnail.
_BOT_DOWNLOAD_MAX_BYTES = 20 * 1024 * 1024
_CAPTION_MAX = 1024
_DIVIDER = "═" * 18
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "gif", "bmp"}

try:
    _TIJUANA = ZoneInfo("America/Tijuana")
except Exception:  # pragma: no cover - tzdata missing on the host
    _TIJUANA = None


def _human_size(size: int) -> str:
    """Format a byte count the way the caption shows it (e.g. "569.6 KB")."""
    value = float(max(size, 0))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            text = f"{value:.1f}".rstrip("0").rstrip(".")
            return f"{text} {unit}"
        value /= 1024
    return f"{size} B"  # pragma: no cover - unreachable


def _extension(filename: str) -> str:
    parts = filename.rsplit(".", 1)
    ext = parts[1].strip().upper() if len(parts) == 2 and parts[1].strip() else ""
    return ext or "FILE"


def _format_date(timestamp: int | None) -> str:
    """Date of the Telegram message, in Tijuana time (e.g. "25 Nov 2026").

    Falls back to UTC when the host has no tzdata for America/Tijuana.
    """
    moment_utc = (
        datetime.fromtimestamp(timestamp, timezone.utc)
        if timestamp is not None
        else datetime.now(timezone.utc)
    )
    moment = moment_utc.astimezone(_TIJUANA) if _TIJUANA is not None else moment_utc
    return f"{moment.day} {_MONTHS[moment.month - 1]} {moment.year}"


def build_fileicon_caption(filename: str, size_bytes: int, timestamp: int | None) -> str:
    """Design 2 — Marco. Never exceeds Telegram's 1024-character caption limit."""
    name = clean_filename(filename)
    head = f"{_DIVIDER}\n<b>📄 "
    tail = (
        f"</b>\n✦ {_human_size(size_bytes)} · {_extension(name)}\n"
        f"✦ {_format_date(timestamp)}\n{_DIVIDER}\n✦ Decode by @GhostDeve"
    )
    escaped = html.escape(name)
    if len(head) + len(escaped) + len(tail) <= _CAPTION_MAX:
        return head + escaped + tail
    budget = _CAPTION_MAX - len(head) - len(tail) - 1  # 1 for "…"
    short = name[: max(budget, 1)]
    while len(head) + len(html.escape(short) + "…") + len(tail) > _CAPTION_MAX and len(short) > 1:
        short = short[:-1]
    return head + html.escape(short) + "…" + tail


def make_thumbnail(raw: bytes) -> bytes | None:
    """Convert an image to a JPEG thumbnail within the Bot API limits."""
    try:
        with Image.open(io.BytesIO(raw)) as image:
            image = ImageOps.exif_transpose(image)
            image = image.convert("RGB")
            image.thumbnail((_THUMB_MAX_PX, _THUMB_MAX_PX), Image.LANCZOS)
            for quality in (92, 85, 75, 65, 55):
                buffer = io.BytesIO()
                image.save(buffer, format="JPEG", quality=quality, optimize=True)
                if buffer.tell() <= _THUMB_MAX_BYTES:
                    return buffer.getvalue()
            return buffer.getvalue()
    except Exception:
        logger.warning("Could not convert the thumbnail image", exc_info=True)
        return None


_Actor = tuple[int, int | None, int]


@dataclass(slots=True)
class _Pending:
    stage: str  # "document" | "thumbnail"
    original: object
    marker: object = field(default_factory=object)
    file_id: str | None = None
    file_name: str | None = None
    file_size: int = 0
    document_date: int | None = None
    timer: Timer | None = None


_pending: dict[_Actor, _Pending] = {}
_lock = Lock()


def _actor(message) -> _Actor | None:
    # Mirrors decoder_credentials._actor: (chat, thread, user).
    chat = getattr(message, "chat", None)
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if (getattr(chat, "type", None) not in {"private", "group", "supergroup"} or
            user_id is None or getattr(message, "sender_chat", None) is not None):
        return None
    return chat.id, getattr(message, "message_thread_id", None), user_id


def _remove(actor: _Actor, marker: object | None = None) -> bool:
    with _lock:
        pending = _pending.get(actor)
        if pending is None or (marker is not None and pending.marker != marker):
            return False
        del _pending[actor]
        if pending.timer is not None:
            pending.timer.cancel()
        return True


def cancel_pending_fileicon(message) -> bool:
    """Cancel a /fileicon flow started by the message author (for /cancel)."""
    actor = _actor(message)
    if actor is None:
        return False
    return _remove(actor)


def _reply(message, text: str):
    return bot.reply_to(message, text, **thread_options(message))


def _begin_session(message) -> bool:
    actor = _actor(message)
    if actor is None:
        return False
    with _lock:
        old = _pending.pop(actor, None)
        if old is not None and old.timer is not None:
            old.timer.cancel()
        if len(_pending) >= _MAX_PENDING:
            return False
        pending = _Pending(stage="document", original=message)
        pending.timer = Timer(_TTL_SECONDS, _remove, args=(actor, pending.marker))
        pending.timer.daemon = True
        _pending[actor] = pending
        pending.timer.start()
    return True


@bot.message_handler(commands=["fileicon"])
@require_authorized
def start_fileicon(message) -> None:
    if _begin_session(message):
        _reply(message, "Send the file you want to attach a thumbnail to.")
    else:
        _reply(message, "The bot is busy. Try /fileicon again in a moment.")


def _is_fileicon_document(message) -> bool:
    actor = _actor(message)
    if actor is None or getattr(message, "document", None) is None:
        return False
    with _lock:
        return actor in _pending


@bot.message_handler(content_types=["document"], func=_is_fileicon_document)
@require_authorized
def handle_fileicon_document(message) -> None:
    actor = _actor(message)
    if actor is None:
        return
    with _lock:
        pending = _pending.get(actor)
    if pending is None:
        return
    document = message.document
    if pending.stage == "document":
        if (getattr(document, "file_size", 0) or 0) > settings.max_file_size_bytes:
            _reply(message, "That file is too large. Send a smaller file.")
            return
        with _lock:
            pending.file_id = document.file_id
            pending.file_name = clean_filename(document.file_name or "file")
            pending.file_size = getattr(document, "file_size", 0) or 0
            pending.document_date = getattr(message, "date", None)
            pending.stage = "thumbnail"
        _reply(message, "File received. Now send the thumbnail image.")
        return
    # Awaiting the thumbnail: an image sent as a document counts as the thumbnail.
    mime = str(getattr(document, "mime_type", "") or "")
    name = clean_filename(document.file_name or "")
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if not (mime.startswith("image/") or ext in _IMAGE_EXTENSIONS):
        _reply(message, "Send the thumbnail image.")
        return
    _deliver(message, pending, document.file_id)


def _is_fileicon_photo(message) -> bool:
    actor = _actor(message)
    if actor is None or not getattr(message, "photo", None):
        return False
    with _lock:
        return actor in _pending


@bot.message_handler(content_types=["photo"], func=_is_fileicon_photo)
@require_authorized
def handle_fileicon_photo(message) -> None:
    actor = _actor(message)
    if actor is None:
        return
    with _lock:
        pending = _pending.get(actor)
    if pending is None:
        return
    if pending.stage == "document":
        _reply(message, "Send the file you want to attach a thumbnail to.")
        return
    photos = message.photo or []
    if not photos:
        return
    _deliver(message, pending, photos[-1].file_id)


def _is_fileicon_text(message) -> bool:
    actor = _actor(message)
    text = getattr(message, "text", None)
    if actor is None or not isinstance(text, str) or not text.strip() or text.startswith("/"):
        return False
    with _lock:
        return actor in _pending


@bot.message_handler(func=_is_fileicon_text)
@require_authorized
def handle_fileicon_text(message) -> None:
    actor = _actor(message)
    if actor is None:
        return
    with _lock:
        pending = _pending.get(actor)
    if pending is None:
        return
    if pending.stage == "document":
        _reply(message, "Send the file you want to attach a thumbnail to.")
    else:
        _reply(message, "Send the thumbnail image.")


def _download(file_id: str) -> bytes | None:
    """Download a Telegram file by file_id; None when it cannot be fetched."""
    try:
        file_info = bot.get_file(file_id)
        return bot.download_file(file_info.file_path)
    except Exception:
        logger.warning("Could not download a Telegram file", exc_info=True)
        return None


def _deliver(message, pending: _Pending, image_file_id: str) -> None:
    actor = _actor(message)
    raw = _download(image_file_id)
    if raw is None:
        _reply(message, "Could not download that image. Send another thumbnail image.")
        return
    thumbnail_bytes = make_thumbnail(raw)
    if thumbnail_bytes is None:
        _reply(message, "That image could not be used as a thumbnail. Send another image.")
        return
    if pending.file_size > _BOT_DOWNLOAD_MAX_BYTES:
        if actor is not None:
            _remove(actor, pending.marker)
        _reply(
            message,
            "That file is too large to attach a thumbnail to: Telegram only lets "
            "the bot download files up to 20 MB. Try /fileicon again with a smaller file.",
        )
        return
    # Re-upload the file bytes: Telegram ignores the thumbnail when a document
    # is re-sent by file_id, so the file would come back with the generic icon.
    document_bytes = _download(pending.file_id) if pending.file_id else None
    if document_bytes is None:
        _reply(message, "Could not download that file to attach the thumbnail. Send it again.")
        return
    caption = build_fileicon_caption(
        pending.file_name or "file", pending.file_size, pending.document_date
    )
    document = io.BytesIO(document_bytes)
    document.name = pending.file_name or "file"
    thumbnail = io.BytesIO(thumbnail_bytes)
    thumbnail.name = "thumbnail.jpg"
    if actor is not None:
        _remove(actor, pending.marker)
    try:
        bot.send_document(
            chat_id=message.chat.id,
            document=document,
            thumbnail=thumbnail,
            caption=caption,
            parse_mode="HTML",
            reply_to_message_id=message.message_id,
            **thread_options(message),
        )
    except Exception:
        logger.warning("Could not send the file with its thumbnail", exc_info=True)
