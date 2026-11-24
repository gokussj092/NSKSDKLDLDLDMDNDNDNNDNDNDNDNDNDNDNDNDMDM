from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from io import BytesIO

from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from spdecode.format_names import public_result_data
from spdecode.utils import split_copy_suffix, thread_options

_RESULT_LINKS = (
    ("Channel", "https://t.me/GhostDeve"),
    ("Group", "https://t.me/CodeBreakersHub"),
    ("Ghost Developer", "https://t.me/Gh0stDeveloper"),
)
_PARTIAL_NOTICE = "Some fields could not be resolved."
_LEGACY_HEADER = re.compile(
    r"\A(?:[ \t]*\n)*┌─+\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘[^\n]*\n"
    r"(?:│(?:𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥|\[۞\] Aplicación:)[^\n]*\n)?├─+\n"
)
_LEGACY_FOOTER = re.compile(
    r"(?:(?:\n[ \t]*)?(?:\n├─+)?\n│\[(?:۞|🚀)\] 𝗚𝗥𝗢𝗨𝗣[^\n]*"
    r"(?:\n├─+)?\n│\[(?:۞|🚀)\] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟[^\n]*)?"
    r"\n└─+\s*\Z"
)
_LEGACY_FIELD = re.compile(r"(?m)^│\[[۞🚀]\] ([^:\r\n]+):[ \t]?")
_TLS_FRAME = re.compile(r"\ATLS Tunnel\n={30}\n\n(.*)\n\n={30}\n?\Z", re.DOTALL)


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


def _result_data(output: str) -> object:
    body, boxed = _LEGACY_HEADER.subn("", output, count=1)
    if boxed:
        body = _LEGACY_FOOTER.sub("", body, count=1)
    else:
        body = _TLS_FRAME.sub(r"\1", body, count=1)

    # Some local link decoders append an import link to a complete JSON value.
    config, separator, link = body.partition("\n\nEncoded configuration:\n")
    try:
        data = json.loads(config)
    except (ValueError, RecursionError):
        pass
    else:
        return {"config": data, "encodedConfiguration": link} if separator else data

    # Legacy decoders label each field and emit nested objects/arrays as JSON.
    # Bare values have ambiguous types, so keep their text verbatim.
    labels = list(_LEGACY_FIELD.finditer(body))
    if not labels or labels[0].start() != 0:
        return {"text": body}
    fields = {}
    for index, label in enumerate(labels):
        key = label[1].rstrip()
        if key in fields:
            return {"text": body}
        end = labels[index + 1].start() if index + 1 < len(labels) else len(body)
        value = body[label.end():end].removesuffix("\n")
        if value.lstrip().startswith(("{", "[")):
            try:
                value = json.loads(value)
            except (ValueError, RecursionError):
                pass
        fields[key] = value
    return fields


def _json_block(output: str, application: str) -> str:
    result = public_result_data(_result_data(output), application)
    try:
        text = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
    except (ValueError, RecursionError):
        text = json.dumps({"text": output}, ensure_ascii=False, indent=2)
    longest_run = max((len(match[0]) for match in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest_run + 1)
    return f"{fence}json\n{text}\n{fence}"


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
    markdown = "\n\n".join((*metadata, links, _json_block(output, application))) + "\n"
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
    with BytesIO(markdown.encode("utf-8", errors="backslashreplace")) as document:
        document.name = f"{stem}.md"
        bot.send_document(
            chat_id=message.chat.id,
            document=document,
            caption=caption,
            reply_to_message_id=message.message_id,
            reply_markup=keyboard,
            **thread_options(message),
        )
