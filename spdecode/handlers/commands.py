from __future__ import annotations

import logging
import re

from telebot.apihelper import ApiTelegramException
from telebot.types import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup

from spdecode.access import can_use_private_chat, is_admin
from spdecode.decoder_runtime import FILE_FORMATS
from spdecode.handlers.format_pages import file_format_rows, text_format_rows
from spdecode.runtime import bot, settings
from spdecode.text_sessions import clear_session, get_session
from spdecode.utils import html_pre, split_message, thread_options

logger = logging.getLogger("sp-decode")

_APP_URL = "https://spdecode.xyz"
_CHANNEL_URL = "https://t.me/GhostDeve"
_DECRYPTION_GROUP_URL = "https://t.me/CodeBreakersHub"
_COMMUNITY_URL = "https://t.me/+N4CnTYwQQ-w0MjNh"
_DEVELOPER_URL = "https://t.me/Gh0stDeveloper"
_MENU_CALLBACK = re.compile(r"menu:(home|files|texts|about):([0-9]{1,3})")
_OLD_MENU_BUTTONS = {"show_files": "files", "show_texts": "texts"}
_ROWS_PER_PAGE = 9


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
    BotCommand("texts", "Show supported text and links"),
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


def configure_bot_commands() -> None:
    """Publish the Telegram command menu without interrupting startup on failure."""
    try:
        bot.set_my_commands(BOT_COMMANDS)
    except Exception:
        logger.exception("Could not update the Telegram command menu")


def _menu_button(label: str, section: str, page: int = 0) -> InlineKeyboardButton:
    return InlineKeyboardButton(label, callback_data=f"menu:{section}:{page}")


def _welcome_view(user) -> tuple[str, InlineKeyboardMarkup]:
    first_name = getattr(user, "first_name", None)
    greeting = f"Welcome to SP-DECODE, {html_pre(first_name)}!" if first_name else "Welcome to SP-DECODE!"
    text = (
        f"<b>{greeting}</b>\n\n"
        "Send a supported file, text, or link to receive the result as a Markdown file.\n\n"
        "On Android, we recommend our SP-DECODE app."
    )
    keyboard = InlineKeyboardMarkup()
    keyboard.row(_menu_button("Files", "files"), _menu_button("Text & Links", "texts"))
    keyboard.row(InlineKeyboardButton("Get the App", url=_APP_URL), _menu_button("About", "about"))
    keyboard.row(
        InlineKeyboardButton("Telegram Channel", url=_CHANNEL_URL),
        InlineKeyboardButton("Decryption Group", url=_DECRYPTION_GROUP_URL),
    )
    return text, keyboard


def _about_view() -> tuple[str, InlineKeyboardMarkup]:
    text = (
        "<b>About SP-DECODE</b>\n\n"
        "<b>Developer and owner</b> · Ghost Developer\n\n"
        "<b>Project history</b>\n"
        "• <b>2024</b> · The SP-DECODE project began.\n"
        "• <b>October 4, 2026</b> · Development resumed after a pause.\n"
        "• <b>October 8, 2026</b> · The project expanded to Android and reached its first working alpha."
    )
    keyboard = InlineKeyboardMarkup()
    keyboard.row(
        InlineKeyboardButton("Telegram Channel", url=_CHANNEL_URL),
        InlineKeyboardButton("Decryption Group", url=_DECRYPTION_GROUP_URL),
    )
    keyboard.row(InlineKeyboardButton("SP-DECODE Community", url=_COMMUNITY_URL))
    keyboard.row(
        InlineKeyboardButton("Ghost Developer", url=_DEVELOPER_URL),
        InlineKeyboardButton("Get the App", url=_APP_URL),
    )
    keyboard.row(_menu_button("Main Menu", "home"))
    return text, keyboard


def _catalogue_view(section: str, page: int) -> tuple[str, InlineKeyboardMarkup]:
    if section == "files":
        title, rows = "Supported files", file_format_rows()
    else:
        title, rows = "Supported text and links", text_format_rows()
    total_pages = max(1, (len(rows) + _ROWS_PER_PAGE - 1) // _ROWS_PER_PAGE)
    page = max(0, min(page, total_pages - 1))
    start = page * _ROWS_PER_PAGE
    lines = [
        f"<b>{title}</b>",
        f"Page {page + 1} of {total_pages}",
        "",
        *rows[start:start + _ROWS_PER_PAGE],
    ]
    keyboard = InlineKeyboardMarkup()
    navigation = []
    if page > 0:
        navigation.append(_menu_button("‹ Previous", section, page - 1))
    if page + 1 < total_pages:
        navigation.append(_menu_button("Next ›", section, page + 1))
    if navigation:
        keyboard.row(*navigation)
    keyboard.row(_menu_button("Main Menu", "home"))
    return "\n".join(lines), keyboard


def _menu_view(section: str, page: int, user) -> tuple[str, InlineKeyboardMarkup]:
    if section == "home":
        return _welcome_view(user)
    if section == "about":
        return _about_view()
    return _catalogue_view(section, page)


def _reply_with_menu(message, section: str) -> None:
    text, keyboard = _menu_view(section, 0, getattr(message, "from_user", None))
    bot.reply_to(message, text, parse_mode="HTML", reply_markup=keyboard, **thread_options(message))


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
    _reply_with_menu(message, "home")

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
        "/texts — supported text and links\n"
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
    _reply_with_menu(message, "files")

@bot.message_handler(commands=["texts", "textos"])
def show_texts(message):
    _reply_with_menu(message, "texts")


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
    _reply_with_menu(message, "about")


@bot.callback_query_handler(
    func=lambda call: call.data in _OLD_MENU_BUTTONS or _MENU_CALLBACK.fullmatch(call.data or "") is not None,
)
def handle_menu_callback(call):
    try:
        bot.answer_callback_query(call.id)
    except ApiTelegramException:
        logger.debug("Could not acknowledge the menu callback")

    if call.message is None:
        return
    section = _OLD_MENU_BUTTONS.get(call.data)
    page = 0
    if section is None:
        match = _MENU_CALLBACK.fullmatch(call.data or "")
        if match is None:
            return
        section, page_number = match.groups()
        page = int(page_number)

    text, keyboard = _menu_view(section, page, getattr(call, "from_user", None))
    try:
        bot.edit_message_text(
            text,
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            parse_mode="HTML",
            reply_markup=keyboard,
        )
    except ApiTelegramException as error:
        if "message is not modified" not in error.description.lower():
            logger.warning("Could not edit the Telegram menu (%s)", error.error_code)
