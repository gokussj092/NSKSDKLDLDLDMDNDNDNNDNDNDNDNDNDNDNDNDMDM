from __future__ import annotations

import html
import re
from pathlib import Path


def clean_filename(filename: str) -> str:
    """Devuelve un nombre seguro sin permitir rutas relativas o absolutas."""
    filename = Path(filename.replace("\\", "/")).name.replace("\x00", "")
    cleaned = re.sub(r"[^\w.()\-\[\] ]+", "_", filename, flags=re.UNICODE).strip()
    return cleaned[:180] or "archivo"


def split_message(message: str, max_length: int = 3500) -> list[str]:
    parts: list[str] = []
    while len(message) > max_length:
        split_index = message.rfind("\n", 0, max_length)
        if split_index == -1:
            split_index = max_length
        parts.append(message[:split_index])
        message = message[split_index:].lstrip()
    if message:
        parts.append(message)
    return parts


def html_pre(text: str) -> str:
    return html.escape(text)


def thread_options(message) -> dict[str, int]:
    thread_id = getattr(message, "message_thread_id", None)
    return {"message_thread_id": thread_id} if thread_id is not None else {}
