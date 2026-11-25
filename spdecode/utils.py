from __future__ import annotations

import html
import re
from pathlib import Path


def clean_filename(filename: str) -> str:
    """Keep the basename and replace control characters for the attachment header."""
    basename = Path(filename.replace("\\", "/")).name
    return re.sub(r"[\x00-\x1f\x7f]", "_", basename).strip() or "file"


def split_copy_suffix(filename: str) -> tuple[str, str]:
    """Separate a trailing copy number from the name used for format detection."""
    match = re.search(r" *\([0-9]+\)$", filename)
    return (filename[:match.start()], match[0]) if match else (filename, "")


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
