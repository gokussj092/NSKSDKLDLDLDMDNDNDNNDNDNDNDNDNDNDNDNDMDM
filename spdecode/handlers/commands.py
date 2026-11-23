from __future__ import annotations

import logging
import re

from telebot.types import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup

from spdecode.access import can_use_private_chat, is_admin
from spdecode.decoder_runtime import FILE_FORMATS, TEXT_FORMATS
from spdecode.runtime import bot, settings
from spdecode.text_sessions import clear_session, get_session
from spdecode.utils import html_pre, split_message, thread_options

logger = logging.getLogger("sp-decode")


def _message_command(message) -> str:
    text = getattr(message, "text", None) or ""
    if not text.startswith("/"):
        return ""
    return text[1:].split("@", 1)[0].split(None, 1)[0]


def _protocol_label(protocol: str) -> str:
    return {"ssc": "SSC Custom", "dark": "Dark Tunnel"}.get(protocol, protocol.upper())


BOT_COMMANDS = [
    BotCommand("start", "Open the main menu"),
    BotCommand("help", "Learn how to use the bot"),
    BotCommand("formats", "Show supported file formats"),
    BotCommand("texts", "Show supported text protocols"),
    BotCommand("session", "Show the current multipart session"),
    BotCommand("ssc", "Show the active SSC session"),
    BotCommand("dark", "Show the active Dark Tunnel session"),
    BotCommand("cancel", "Cancel the pending session"),
    BotCommand("id", "Show your user ID and chat ID"),
    BotCommand("allowgroup", "Authorize a group (administrators)"),
    BotCommand("revokegroup", "Remove a group from the allowlist (administrators)"),
    BotCommand("restrictgroups", "Restrict access to allowed groups (administrators)"),
    BotCommand("private", "Check or manage private chat access"),
    BotCommand("ping", "Check whether the bot is online"),
    BotCommand("status", "Show bot status (administrators)"),
    BotCommand("about", "About SP-DECODE"),
]


TEXT_PROTOCOLS = (
    "<b>Supported text protocols</b>\n\n"
    "<b>SSC Custom</b>\n"
    "<code>ssc://...</code> — send it in as many messages as needed.\n\n"
    "<b>TLS Tunnel</b>\n"
    "<code>tls://...</code> — send the complete configuration in one message.\n\n"
    "<b>Dark Tunnel</b>\n"
    "Send a link such as <code>dark://...</code> or <code>darktunnel://...</code>. "
    "You can split it across multiple messages.\n\n"
    "<b>NetMod</b>\n"
    "<code>nm-vmess://</code>, <code>nm-vless://</code>, <code>nm-dns://</code>, "
    "<code>nm-trojan://</code>, <code>nm-ssh://</code>, <code>nm-ssr://</code>, "
    "<code>nm-xray-json://</code>\n\n"
    "<b>ARMOD</b>\n"
    "<code>ar-dns://</code>, <code>ar-vless://</code>, <code>ar-vmess://</code>, "
    "<code>ar-trojan://</code>, <code>ar-ssr://</code>, <code>ar-trojan-go://</code>, "
    "<code>ar-ssh://</code>\n\n"
    "<b>Howdy</b>\n"
    "<code>howdy://</code>, <code>N7pr://</code>\n\n"
    "<b>XrayPB</b>\n"
    "<code>pb-vmess://</code>, <code>pb-ss://</code>, <code>pb-socks://</code>, "
    "<code>pb-vless://</code>, <code>pb-trojan://</code>, <code>pb-ssh://</code>\n\n"
    "<b>Other protocols</b>\n"
    "<code>vmess://</code>, <code>zivpn://</code>, <code>v2box://locked=...</code>"
)


def configure_bot_commands() -> None:
    """Publish the Telegram command menu without interrupting startup on failure."""
    try:
        bot.set_my_commands(BOT_COMMANDS)
    except Exception:
        logger.exception("Could not update the Telegram command menu")


def _main_keyboard() -> InlineKeyboardMarkup:
    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("File formats", callback_data="show_files"),
        InlineKeyboardButton("Text protocols", callback_data="show_texts"),
        InlineKeyboardButton("Channel", url="https://t.me/GhostDeve"),
        InlineKeyboardButton("Group", url="https://t.me/CodeBreakersHub"),
        InlineKeyboardButton("Developer", url="https://t.me/Gh0stDeveloper"),
        InlineKeyboardButton("GitHub", url="https://github.com/Gh0stDeveloper"),
    )
    return keyboard


def _format_registry() -> str:
    lines = [
        "<b>Supported file formats</b>",
        f"Total: <b>{len(FILE_FORMATS)}</b>",
        "",
    ]
    for extension, spec in sorted(
        FILE_FORMATS.items(),
        key=lambda item: (item[1]["name"].casefold(), item[0].casefold()),
    ):
        lines.append(
            f"<b>{html_pre(spec['name'])}</b> — <code>.{html_pre(extension)}</code>"
        )
    return "\n".join(lines)


def _send_html_parts(
    chat_id: int, text: str, *, reply_to_message_id: int | None = None,
    message_thread_id: int | None = None,
) -> None:
    for index, part in enumerate(split_message(text, max_length=3900), start=1):
        kwargs = {"chat_id": chat_id, "text": part, "parse_mode": "HTML"}
        if message_thread_id is not None:
            kwargs["message_thread_id"] = message_thread_id
        if index == 1 and reply_to_message_id is not None:
            kwargs["reply_to_message_id"] = reply_to_message_id
        bot.send_message(**kwargs)


@bot.message_handler(commands=["start"])
def send_welcome(message):
    text = (
        "<b>SP-DECODE</b>\n"
        "Decode supported configuration files, text and links.\n\n"
        "For SSC Custom and Dark Tunnel, send the full text in one message or split it "
        "across multiple messages. The bot assembles the fragments automatically.\n\n"
        "Use /help for instructions, /formats for file formats and /texts for text protocols."
    )
    bot.reply_to(message, text, parse_mode="HTML", reply_markup=_main_keyboard())


@bot.message_handler(commands=["help", "ayuda"])
def show_help(message):
    text = (
        "<b>How to use SP-DECODE</b>\n\n"
        "Send a supported file, text or link. The bot replies with a Markdown (.md) file. "
        "For files, it keeps the original name and replaces the extension with .md. "
        "If the bot asks for a credential, reply to the prompt in the same chat.\n\n"
        "<b>SSC and Dark Tunnel text</b>\n"
        "Send the full text or its first fragment with the appropriate prefix. "
        "Send any remaining fragments in order. The bot tries to decode the text after each fragment "
        "and closes the session when decoding succeeds. Use /session to check progress or /cancel to discard it.\n\n"
        "<b>Commands</b>\n"
        "/formats — supported file formats\n"
        "/texts — supported text protocols\n"
        "/id — user and chat IDs\n"
        "/allowgroup — authorize a group (administrators)\n"
        "/revokegroup — remove a group from the allowlist (administrators)\n"
        "/restrictgroups — allow only groups on the allowlist (administrators)\n"
        "/private — check or manage private chat access\n"
        "/ping — check whether the bot is online\n"
        "/about — about SP-DECODE"
    )
    bot.reply_to(message, text, parse_mode="HTML")


@bot.message_handler(commands=["formats", "archivos"])
def show_formats(message):
    _send_html_parts(
        message.chat.id,
        _format_registry(),
        reply_to_message_id=message.message_id,
    )


def _send_text_formats(chat_id, *, reply_to_message_id=None):
    lines = [TEXT_PROTOCOLS, "", "<b>Formats shared with Cloud</b>"]
    for prefix, label in sorted(TEXT_FORMATS.items(), key=lambda item: (item[1].casefold(), item[0])):
        lines.append(f"<b>{html_pre(label)}</b> — <code>{html_pre(prefix)}</code>")
    _send_html_parts(chat_id, "\n".join(lines), reply_to_message_id=reply_to_message_id)


@bot.message_handler(commands=["texts", "textos"])
def show_texts(message):
    _send_text_formats(message.chat.id, reply_to_message_id=message.message_id)


@bot.message_handler(commands=["session", "sesion", "ssc", "dark"])
def show_text_session(message):
    session = get_session(message, settings.text_session_timeout_seconds)
    requested = (_message_command(message) or "session").lower()

    if session is None:
        bot.reply_to(
            message,
            "<b>Text sessions</b>\nYou have no pending multipart session in this chat.",
            parse_mode="HTML",
        )
        return

    if requested == "ssc" and session.protocol != "ssc":
        bot.reply_to(
            message,
            "<b>SSC</b>\nThere is no active SSC session. The pending session is for "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b>.",
            parse_mode="HTML",
        )
        return

    if requested == "dark" and session.protocol != "dark":
        bot.reply_to(
            message,
            "<b>Dark Tunnel</b>\nThere is no active Dark Tunnel session. The pending session is for "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b>.",
            parse_mode="HTML",
        )
        return


    bot.reply_to(
        message,
        f"<b>Active {_protocol_label(session.protocol)} session</b>\n"
        f"Fragments received: <b>{session.parts}</b>\n"
        f"Characters received: <b>{session.char_count:,}</b>\n\n"
        "The bot tries to decode the text after each fragment. Use /cancel to discard the session.",
        parse_mode="HTML",
    )


@bot.message_handler(commands=["cancel", "cancelar"])
def cancel_pending_session(message):
    from spdecode.handlers.decoder_credentials import cancel_pending_credentials

    credentials_canceled = cancel_pending_credentials(message)
    session = get_session(message, settings.text_session_timeout_seconds)
    if session is not None and clear_session(message):
        bot.reply_to(
            message,
            f"<b>Session canceled</b>\nThe pending "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b> text was discarded.",
            parse_mode="HTML",
        )
    elif credentials_canceled:
        bot.reply_to(message, "Credential request canceled.", **thread_options(message))
    else:
        bot.reply_to(
            message,
            "There was no pending session to cancel.",
            parse_mode="HTML",
        )


@bot.message_handler(commands=["id"])
def show_ids(message):
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    bot.reply_to(
        message,
        "<b>Telegram IDs</b>\n"
        f"User: <code>{user_id}</code>\n"
        f"Chat: <code>{chat_id}</code>",
        parse_mode="HTML",
    )


def _telegram_id(value: str, *, group: bool) -> int | None:
    if re.fullmatch(r"-?[1-9][0-9]{0,15}", value) is None:
        return None
    identifier = int(value)
    if abs(identifier) < 2**52 and (identifier < 0) == group:
        return identifier
    return None


def _permission_reply(message, text: str) -> None:
    bot.reply_to(message, text, **thread_options(message))


@bot.message_handler(commands=["allowgroup", "revokegroup", "permitirgrupo", "revocargrupo"])
def manage_group_permission(message):
    from spdecode.runtime import set_chat_permission, settings as current_settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if not is_admin(user_id, current_settings):
        _permission_reply(message, "Only SP-DECODE administrators can change group permissions.")
        return

    allowed = _message_command(message) in {"allowgroup", "permitirgrupo"}
    args = (message.text or "").split()[1:]
    if len(args) == 1:
        group_id = _telegram_id(args[0], group=True)
    elif not args and message.chat.type in {"group", "supergroup"}:
        group_id = _telegram_id(str(message.chat.id), group=True)
    else:
        group_id = None
    if group_id is None:
        command = "allowgroup" if allowed else "revokegroup"
        _permission_reply(message, f"Use /{command} in the group or follow it with the group's negative ID.")
        return
    try:
        changed = set_chat_permission(group_id, allowed)
    except (OSError, ValueError):
        _permission_reply(message, "Could not save the group permission.")
        return

    if allowed:
        result = "Group added to the allowlist." if changed else "The group is already on the allowlist."
    else:
        result = "Group removed from the allowlist." if changed else "The group was not on the allowlist."
    if current_settings.allow_all_groups:
        result += " All-groups access is enabled. Use /restrictgroups to enforce the allowlist."
    _permission_reply(message, result)


@bot.message_handler(commands=["restrictgroups"])
def restrict_group_access(message):
    from spdecode.runtime import restrict_groups, settings as current_settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if not is_admin(user_id, current_settings):
        _permission_reply(message, "Only SP-DECODE administrators can change group access.")
        return

    if len((message.text or "").split()) != 1:
        _permission_reply(message, "Use /restrictgroups to restrict access to allowed groups.")
        return

    try:
        changed = restrict_groups()
    except (OSError, ValueError):
        _permission_reply(message, "Could not save the group access mode.")
        return

    result = "Group access is now restricted to allowed groups." if changed else (
        "Group access is already restricted to allowed groups."
    )
    _permission_reply(message, result)


@bot.message_handler(commands=["private", "privados"])
def manage_private_permissions(message):
    from spdecode.runtime import set_chat_permission, settings as current_settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    args = (message.text or "").split()[1:]
    if not is_admin(user_id, current_settings):
        if args:
            _permission_reply(message, "Only SP-DECODE administrators can manage private chat permissions.")
        else:
            allowed = can_use_private_chat(user_id, current_settings)
            _permission_reply(message, "Your account can use the bot in private chats." if allowed else
                              "Your account needs permission to use the bot in private chats.")
        return

    if not args:
        admins = ", ".join(map(str, sorted(current_settings.admins))) or "None"
        users = ", ".join(map(str, sorted(current_settings.allowed_private_users - current_settings.admins))) or "None"
        _send_html_parts(
            message.chat.id,
            f"<b>Private chat access</b>\nAdministrators: {admins}\nAllowed users: {users}\n\n"
            "/private allow ID · /private revoke ID",
            reply_to_message_id=message.message_id,
            **thread_options(message),
        )
        return

    target = _telegram_id(args[1], group=False) if len(args) == 2 else None
    if target is None or args[0] not in {"allow", "revoke", "permitir", "revocar"}:
        _permission_reply(message, "Use /private allow ID or /private revoke ID with a positive user ID.")
        return
    if is_admin(target, current_settings):
        _permission_reply(message, "This user has access as an administrator.")
        return
    allowed = args[0] in {"allow", "permitir"}
    try:
        changed = set_chat_permission(target, allowed)
    except (OSError, ValueError):
        _permission_reply(message, "Could not save the private chat permission.")
        return

    if allowed:
        result = "Private chat access granted." if changed else "The user already has private chat access."
    else:
        result = "Private chat access revoked." if changed else "The user did not have private chat access."
    _permission_reply(message, result)


@bot.message_handler(commands=["ping"])
def ping(message):
    bot.reply_to(
        message,
        "<b>SP-DECODE is online</b>\nThe bot is receiving and processing messages.",
        parse_mode="HTML",
    )


@bot.message_handler(commands=["status"])
def show_status(message):
    from spdecode.runtime import settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if not is_admin(user_id, settings):
        bot.reply_to(
            message,
            "<b>Restricted access</b>\nThis command is available to administrators only.",
            parse_mode="HTML",
        )
        return

    session = get_session(message, settings.text_session_timeout_seconds)
    session_status = _protocol_label(session.protocol) if session is not None else "none"
    group_access = (
        "all groups and supergroups"
        if settings.allow_all_groups
        else f"allowlist only ({len(settings.allowed_groups)} groups)"
    )
    bot.reply_to(
        message,
        "<b>SP-DECODE status</b>\n"
        "Status: <b>online</b>\n"
        f"Administrators: <b>{len(settings.admins)}</b>\n"
        f"Group access: <b>{html_pre(group_access)}</b>\n"
        f"Allowed private chat users: <b>{len(settings.allowed_private_users)}</b>\n"
        f"Registered file formats: <b>{len(FILE_FORMATS)}</b>\n"
        f"Multipart session for this chat and user: <b>{html_pre(session_status)}</b>\n"
        f"Decoder timeout: <b>{settings.decoder_timeout_seconds}s</b>",
        parse_mode="HTML",
    )


@bot.message_handler(commands=["about"])
def about(message):
    bot.reply_to(
        message,
        "<b>SP-DECODE</b>\n"
        "Configuration decoder bot powered by Python, Node.js and PHP.\n\n"
        "Developer: @Gh0stDeveloper\n"
        "Channel: @GhostDeve\n"
        "Group: @CodeBreakersHub",
        parse_mode="HTML",
        reply_markup=_main_keyboard(),
    )


@bot.callback_query_handler(func=lambda call: call.data == "show_files")
def handle_supported_files(call):
    try:
        bot.answer_callback_query(call.id)
    except Exception:
        pass
    _send_html_parts(call.message.chat.id, _format_registry())


@bot.callback_query_handler(func=lambda call: call.data == "show_texts")
def handle_supported_texts(call):
    try:
        bot.answer_callback_query(call.id)
    except Exception:
        pass
    _send_text_formats(call.message.chat.id)
