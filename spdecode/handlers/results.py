from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from io import BytesIO

from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from spdecode.format_names import public_result_output
from spdecode.utils import split_copy_suffix, thread_options

_RESULT_LINKS = (
    ("Channel", "https://t.me/GhostDeve"),
    ("Group", "https://t.me/CodeBreakersHub"),
    ("Ghost Developer", "https://t.me/Gh0stDeveloper"),
)
_PARTIAL_NOTICE = "Some fields could not be resolved."


def _markdown_label(value: str) -> str:
    return re.sub(r"([\\`*_{}\[\]<>|&])", r"\\\1", " ".join(value.split()))


def _request_author(message: Message) -> tuple[str, str]:
    author = getattr(message, "sender_chat", None) or getattr(message, "from_user", None)
    username = getattr(author, "username", None)
    if username and re.fullmatch(r"[A-Za-z0-9_]{1,32}", username):
        return f"@{username}", f"[@{username}](https://t.me/{username})"

    name = getattr(author, "title", None) or " ".join(
        part for part in (getattr(author, "first_name", None), getattr(author, "last_name", None)) if part
    )
    name = " ".join(name.split()) or "Telegram user"
    return name, _markdown_label(name)


def _code_block(text: str, language: str = "") -> str:
    # Keep the decoded content literal even when it contains Markdown delimiters.
    longest_run = max((len(match[0]) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest_run + 1)
    if not text.endswith("\n"):
        text += "\n"
    return f"{fence}{language}\n{text}{fence}"


def _legacy_result_blocks(output: str) -> str:
    """Highlight compact JSON values inside legacy key-value output."""
    blocks = []
    cursor = 0
    for label in re.finditer(r"(?m)^│\[۞\] [^:\r\n]+:[ \t]*(?=[{\[])", output):
        start = label.end()
        newline = output.find("\n", start)
        stop = len(output) if newline == -1 else newline + 1
        value = output[start:stop]
        try:
            json.loads(value)
        except (ValueError, RecursionError):
            continue
        blocks.extend((_code_block(output[cursor:start]), _code_block(value, "json")))
        cursor = stop
    if cursor < len(output) or not blocks:
        blocks.append(_code_block(output[cursor:]))
    return "\n\n".join(blocks)


def _result_blocks(output: str) -> str:
    start = re.search(r"(?m)^[ \t]*(?=[{\[])", output)
    if start is None:
        return _legacy_result_blocks(output)

    try:
        _, end = json.JSONDecoder().raw_decode(output, start.end())
    except (ValueError, RecursionError):
        return _legacy_result_blocks(output)

    # Some decoders surround their JSON with a banner or append import links.
    newline = output.find("\n", end)
    stop = len(output) if newline == -1 else newline + 1
    if output[end:stop].strip():
        return _legacy_result_blocks(output)
    before, after = output[:start.start()], output[stop:]
    if not (before.strip() or after.strip()):
        return _code_block(output, "json")
    parts = ((before, ""), (output[start.start():stop], "json"), (after, ""))
    return "\n\n".join(_code_block(text, language) for text, language in parts if text.strip())


def send_markdown_result(
    message: Message, application: str, output: str, *, source_file: str | None = None, partial: bool = False,
) -> None:
    from spdecode.runtime import bot

    author, author_label = _request_author(message)
    date = getattr(message, "date", None)
    sent_at = "Unknown" if date is None else datetime.fromtimestamp(date, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    metadata = [
        "# SP-DECODE · Result",
        f"**Application:** {_markdown_label(application)}",
        f"**Sent by:** {author_label}",
        f"**Sent at:** {sent_at}",
    ]
    if source_file:
        metadata.append(f"**Original file:** {_markdown_label(source_file)}")
    if partial:
        metadata.append(f"**Partial result.** {_PARTIAL_NOTICE}")

    links = " · ".join(f"[{label}]({url})" for label, url in _RESULT_LINKS)
    markdown = "\n\n".join((*metadata, links, _result_blocks(public_result_output(output, application)))) + "\n"
    keyboard = InlineKeyboardMarkup(row_width=3)
    keyboard.add(*(InlineKeyboardButton(label, url=url) for label, url in _RESULT_LINKS))
    caption = f"SP-DECODE\nApplication: {application}\nSent by: {author}\nSent at: {sent_at}"
    if partial:
        caption += f"\nPartial result. {_PARTIAL_NOTICE}"

    if source_file:
        base_name, copy_suffix = split_copy_suffix(source_file)
        stem = (base_name.rpartition(".")[0] or base_name) + copy_suffix
    else:
        app_prefix = re.sub(r"[^\w.-]+", "-", application).strip("._-") or "SP-DECODE"
        stem = f"{app_prefix}-spdecode-result"
    with BytesIO(markdown.encode("utf-8")) as document:
        document.name = f"{stem}.md"
        bot.send_document(
            chat_id=message.chat.id,
            document=document,
            caption=caption,
            reply_to_message_id=message.message_id,
            reply_markup=keyboard,
            **thread_options(message),
        )
