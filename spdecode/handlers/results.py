from __future__ import annotations

from ast import literal_eval
import json
import re
from datetime import datetime, timezone
from io import BytesIO
from xml.etree import ElementTree

from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from spdecode.format_names import public_result_data
from spdecode.utils import split_copy_suffix, thread_options

_RESULT_LINKS = (
    ("Channel", "https://t.me/GhostDeve"),
    ("Group", "https://t.me/CodeBreakersHub"),
    ("Ghost Developer", "https://t.me/Gh0stDeveloper"),
)
_PARTIAL_NOTICE = "Some fields could not be resolved."
_LEGACY_GLYPH = r"[۞💠🔵💀🤖😈🔥🚀🔐]"
_LEGACY_HEADER = re.compile(
    r"\A(?:[ \t]*\n)*┌─+\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘[^\n]*\n"
    r"(?:│(?:𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥|\[۞\] Aplicación:)[^\n]*\n)?├─+(?:\n|(?=│\[|[ \t]*<entry ))"
)
_LEGACY_FOOTER = re.compile(
    rf"(?:(?:\n[ \t]*)?(?:\n├─+)?\n│\[{_LEGACY_GLYPH}\] 𝗚𝗥𝗢𝗨𝗣[^\n]*"
    rf"(?:\n├─+)?\n│\[{_LEGACY_GLYPH}\] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟[^\n]*)?"
    r"\n└─+\s*\Z"
)
_LEGACY_FIELD = re.compile(rf"(?m)^│\[{_LEGACY_GLYPH}\] ([^:\r\n]+):[ \t]?")
_SSH_UNLOCK_HEADING = re.compile(rf"(?m)^│\[{_LEGACY_GLYPH}\] unlockKeys 🔽\n")
_LEGACY_XML_ENTRY = re.compile(r'(?m)^[ \t]*<entry key="([^:"\r\n]+)">([^\r\n]*)</entry>[ \t]*$')
_GOLD_FRAME = re.compile(
    r"\A╔[^\n]*\n[╠╚][^\n]*(?:\n[╠╚][^\n]*)*\n\n"
    r"╔[^\n]*\n╠▸ App Name : `Gold Tunnel`\n╚[^\n]*\n\n"
)
_TLS_FRAME = re.compile(r"\ATLS Tunnel\n={30}\n\n(.*)\n\n={30}\n?\Z", re.DOTALL)
_CLOUD_JSON_APPS = {"Dark Tunnel", "ZiVPN Tunnel"}
_JSON_NUMBER = re.compile(r"-?(0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_ZIVPN_PROPERTIES_DTD = re.compile(
    r"""<!DOCTYPE\s+properties\s+SYSTEM\s+(['"])http://java\.sun\.com/dtd/properties\.dtd\1\s*>"""
)


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


def _inline_json(value: str, *, primitives: bool = False) -> object:
    trimmed = value.strip()
    if trimmed.startswith(("{", "[")) or (
        primitives and (trimmed in {"true", "false", "null"} or _JSON_NUMBER.fullmatch(trimmed))
    ):
        try:
            return json.loads(trimmed)
        except (ValueError, RecursionError):
            pass
    return value


def _expand_json_containers(value: object, depth: int = 0) -> object:
    # SP-DECODE Cloud's JSON viewer expands serialized objects and arrays.
    if depth >= 200:
        return value
    if isinstance(value, str):
        value = _inline_json(value)
    if isinstance(value, dict):
        return {key: _expand_json_containers(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_json_containers(item, depth + 1) for item in value]
    return value


def _zivpn_properties(output: str) -> dict[str, str] | None:
    xml = output.strip().removeprefix("\ufeff").lstrip()
    if not xml.startswith("<"):
        return None
    # Accept the standard Java Properties declaration without processing DTDs.
    xml = _ZIVPN_PROPERTIES_DTD.sub("", xml, count=1)
    if "<!DOCTYPE" in xml or "<!ENTITY" in xml:
        return None
    if re.match(r"<entry\b", xml):
        xml = f"<properties>{xml}</properties>"
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, LookupError, ValueError):
        return None
    if root.tag not in {"map", "properties"}:
        return None
    fields = {}
    for entry in root:
        if entry.tag == "comment":
            continue
        key = entry.get("key")
        if entry.tag != "entry" or key is None or len(entry):
            return None
        fields[key] = entry.text or ""
    return fields or None


def _result_data(output: str, application: str) -> object:
    body, boxed = _LEGACY_HEADER.subn("", output, count=1)
    if boxed:
        body = _LEGACY_FOOTER.sub("", body, count=1)
        body = _SSH_UNLOCK_HEADING.sub("", body, count=1)
        body = _LEGACY_XML_ENTRY.sub(r"│[۞] \1: \2", body)
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

    if application == "ZiVPN Tunnel":
        properties = _zivpn_properties(body)
        if properties is not None:
            return properties

    # Gold Tunnel's legacy CLI prints a Python dictionary beneath its frame.
    gold = _GOLD_FRAME.match(body)
    if gold and len(body) - gold.end() <= 128 * 1024:
        try:
            data = literal_eval(body[gold.end():].strip())
        except (ValueError, SyntaxError, RecursionError):
            pass
        else:
            if isinstance(data, dict):
                return data

    # Legacy decoders label each field and emit nested objects/arrays as JSON.
    # Restore bare primitive types only for formats following the Cloud viewer.
    labels = list(_LEGACY_FIELD.finditer(body))
    if not labels or labels[0].start() != 0:
        return {"text": body}
    primitives = application in _CLOUD_JSON_APPS
    fields = {}
    for index, label in enumerate(labels):
        key = label[1].rstrip()
        end = labels[index + 1].start() if index + 1 < len(labels) else len(body)
        value = body[label.end():end].removesuffix("\n")
        fields.setdefault(key, []).append(_inline_json(value, primitives=primitives))
    return {key: values[0] if len(values) == 1 else values for key, values in fields.items()}


def _json_block(output: str, application: str) -> str:
    result = public_result_data(_result_data(output, application), application)
    try:
        if application in _CLOUD_JSON_APPS:
            result = _expand_json_containers(result)
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
