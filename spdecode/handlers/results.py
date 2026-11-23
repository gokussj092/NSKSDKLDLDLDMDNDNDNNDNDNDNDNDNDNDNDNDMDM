from __future__ import annotations

import re
from io import BytesIO

from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from spdecode.utils import thread_options

_RESULT_LINKS = (
    ("Channel", "https://t.me/GhostDeve"),
    ("Group", "https://t.me/CodeBreakersHub"),
    ("Ghost Developer", "https://t.me/Gh0stDeveloper"),
)
_PARTIAL_NOTICE = "Some fields could not be resolved."


def _markdown_label(value: str) -> str:
    return re.sub(r"([\\`*_{}\[\]<>|&])", r"\\\1", " ".join(value.split()))


def _request_author(message: Message) -> str:
    author = getattr(message, "sender_chat", None) or getattr(message, "from_user", None)
    username = getattr(author, "username", None)
    if username and re.fullmatch(r"[A-Za-z0-9_]{1,32}", username):
        return f"[@{username}](https://t.me/{username})"

    name = getattr(author, "title", None) or " ".join(
        part for part in (getattr(author, "first_name", None), getattr(author, "last_name", None)) if part
    )
    return _markdown_label(name) or "Telegram user"


def send_markdown_result(
    message: Message, title: str, output: str, *, source_file: str | None = None, partial: bool = False,
) -> None:
    from spdecode.runtime import bot

    # Keep the decoded text literal, including Markdown delimiters and links.
    longest_run = max((len(match[0]) for match in re.finditer(r"`+", output)), default=0)
    fence = "`" * max(3, longest_run + 1)
    if not output.endswith("\n"):
        output += "\n"

    metadata = [
        "# SP-DECODE · Result",
        "",
        f"**Format:** {_markdown_label(title)}",
        f"**Requested by:** {_request_author(message)}",
    ]
    if source_file:
        metadata.append(f"**Original file:** {_markdown_label(source_file)}")
    if partial:
        metadata.append(f"**Partial result.** {_PARTIAL_NOTICE}")

    links = " · ".join(f"[{label}]({url})" for label, url in _RESULT_LINKS)
    markdown = "\n".join((*metadata, "", links, "", fence, output + fence, ""))
    keyboard = InlineKeyboardMarkup(row_width=3)
    keyboard.add(*(InlineKeyboardButton(label, url=url) for label, url in _RESULT_LINKS))
    caption = f"SP-DECODE · {title}"
    if partial:
        caption += f"\nPartial result. {_PARTIAL_NOTICE}"

    stem = source_file.rpartition(".")[0] if source_file else ""
    with BytesIO(markdown.encode("utf-8")) as document:
        document.name = f"{stem or 'spdecode-result'}.md"
        bot.send_document(
            chat_id=message.chat.id,
            document=document,
            caption=caption,
            reply_to_message_id=message.message_id,
            reply_markup=keyboard,
            **thread_options(message),
        )
