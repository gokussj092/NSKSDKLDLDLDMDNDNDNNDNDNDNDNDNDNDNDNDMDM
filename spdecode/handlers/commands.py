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
    BotCommand("start", "Abrir el menú principal"),
    BotCommand("help", "Ver cómo utilizar el bot"),
    BotCommand("formats", "Ver formatos de archivo soportados"),
    BotCommand("texts", "Ver protocolos de texto soportados"),
    BotCommand("session", "Ver el estado de una cadena dividida"),
    BotCommand("ssc", "Ver la sesión SSC activa"),
    BotCommand("dark", "Ver la sesión Dark Tunnel activa"),
    BotCommand("cancel", "Cancelar la cadena pendiente"),
    BotCommand("id", "Mostrar tu ID y el ID del chat"),
    BotCommand("permitirgrupo", "Autorizar un grupo (administradores)"),
    BotCommand("revocargrupo", "Retirar permiso de grupo (administradores)"),
    BotCommand("privados", "Consultar o gestionar acceso al chat privado"),
    BotCommand("ping", "Comprobar si el bot está activo"),
    BotCommand("status", "Estado interno para administradores"),
    BotCommand("about", "Información de SP-DECODE"),
]


TEXT_PROTOCOLS = (
    "<b>Protocolos de texto soportados</b>\n\n"
    "<b>SSC Custom</b>\n"
    "<code>ssc://...</code> — admite 1, 2, 3 o más mensajes, según sea necesario.\n\n"
    "<b>TLS Tunnel</b>\n"
    "<code>tls://...</code> — configuración completa en un solo mensaje.\n\n"
    "<b>Dark Tunnel</b>\n"
    "Enlaces con un esquema que identifique Dark Tunnel, por ejemplo "
    "<code>dark://...</code> o <code>darktunnel://...</code>. "
    "También admite una cantidad variable de fragmentos.\n\n"
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
    "<b>Otros</b>\n"
    "<code>vmess://</code>, <code>zivpn://</code>, <code>v2box://locked=...</code>"
)


def configure_bot_commands() -> None:
    """Publica el menú de comandos de Telegram; un fallo aquí no detiene el bot."""
    try:
        bot.set_my_commands(BOT_COMMANDS)
    except Exception:
        logger.exception("No se pudo actualizar el menú de comandos de Telegram")


def _main_keyboard() -> InlineKeyboardMarkup:
    keyboard = InlineKeyboardMarkup(row_width=2)
    keyboard.add(
        InlineKeyboardButton("Formatos de archivo", callback_data="show_files"),
        InlineKeyboardButton("Protocolos de texto", callback_data="show_texts"),
        InlineKeyboardButton("Canal", url="https://t.me/GhostDeve"),
        InlineKeyboardButton("Grupo", url="https://t.me/CodeBreakersHub"),
        InlineKeyboardButton("Desarrollador", url="https://t.me/Gh0stDeveloper"),
        InlineKeyboardButton("GitHub", url="https://github.com/Gh0stDeveloper"),
    )
    return keyboard


def _format_registry() -> str:
    lines = [
        "<b>Formatos de archivo soportados</b>",
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
        "Decodificador de archivos y configuraciones de texto.\n\n"
        "Puedes enviar directamente un archivo compatible o una cadena de texto soportada. "
        "Para SSC Custom y Dark Tunnel, el bot puede reconstruir automáticamente una cadena "
        "que llegue completa en un mensaje o dividida en cualquier cantidad de fragmentos.\n\n"
        "Usa /help para ver el flujo de uso, /formats para los archivos soportados y "
        "/texts para los protocolos de texto."
    )
    bot.reply_to(message, text, parse_mode="HTML", reply_markup=_main_keyboard())


@bot.message_handler(commands=["help", "ayuda"])
def show_help(message):
    text = (
        "<b>Cómo utilizar SP-DECODE</b>\n\n"
        "<b>Archivos</b>\n"
        "Envía un documento con una extensión soportada. El bot detectará el decodificador, "
        "lo ejecutará y devolverá el resultado en el chat y como archivo de texto. "
        "Si hace falta una credencial, responde a la solicitud que aparece junto al archivo.\n\n"
        "<b>SSC y Dark Tunnel por texto</b>\n"
        "1. Envía la cadena completa o su primer fragmento con el prefijo correspondiente.\n"
        "2. Si está incompleta, continúa enviando los fragmentos siguientes en orden.\n"
        "3. No existe una cantidad fija: puede completarse con 1, 2, 3 o más mensajes.\n"
        "4. El bot intenta descifrar después de cada fragmento y cierra la sesión cuando el resultado es válido.\n"
        "5. Usa /session para consultar la cadena pendiente o /cancel para descartarla.\n\n"
        "<b>Comandos útiles</b>\n"
        "/formats — archivos soportados\n"
        "/texts — textos soportados\n"
        "/id — IDs de usuario y chat\n"
        "/permitirgrupo — autorizar un grupo (administradores)\n"
        "/privados — consultar acceso al bot por privado\n"
        "/ping — comprobar el bot\n"
        "/about — información del proyecto"
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
    lines = [TEXT_PROTOCOLS, "", "<b>Formatos compartidos con Cloud</b>"]
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
            "<b>Sesiones de texto</b>\nNo tienes ninguna cadena multipart pendiente en este chat.",
            parse_mode="HTML",
        )
        return

    if requested == "ssc" and session.protocol != "ssc":
        bot.reply_to(
            message,
            "<b>SSC</b>\nNo hay una sesión SSC activa. La sesión pendiente corresponde a "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b>.",
            parse_mode="HTML",
        )
        return

    if requested == "dark" and session.protocol != "dark":
        bot.reply_to(
            message,
            "<b>Dark Tunnel</b>\nNo hay una sesión Dark Tunnel activa. La sesión pendiente corresponde a "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b>.",
            parse_mode="HTML",
        )
        return


    bot.reply_to(
        message,
        f"<b>Sesión {_protocol_label(session.protocol)} activa</b>\n"
        f"Partes recibidas: <b>{session.parts}</b>\n"
        f"Caracteres acumulados: <b>{session.char_count:,}</b>\n\n"
        "El bot intentará descifrar nuevamente después de cada fragmento. "
        "No hay una cantidad fija de partes. Usa /cancel para descartar la sesión.",
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
            f"<b>Sesión cancelada</b>\nLa cadena pendiente de "
            f"<b>{html_pre(_protocol_label(session.protocol))}</b> fue eliminada.",
            parse_mode="HTML",
        )
    elif credentials_canceled:
        bot.reply_to(message, "Solicitud de credenciales cancelada.", **thread_options(message))
    else:
        bot.reply_to(
            message,
            "<b>Sin cambios</b>\nNo había ninguna sesión pendiente.",
            parse_mode="HTML",
        )


@bot.message_handler(commands=["id"])
def show_ids(message):
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    bot.reply_to(
        message,
        "<b>Identificadores</b>\n"
        f"Usuario: <code>{user_id}</code>\n"
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


@bot.message_handler(commands=["permitirgrupo", "revocargrupo"])
def manage_group_permission(message):
    from spdecode.runtime import set_chat_permission, settings as current_settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if not is_admin(user_id, current_settings):
        _permission_reply(message, "Solo los administradores de SP-DECODE pueden cambiar permisos de grupo.")
        return

    command = _message_command(message)
    args = (message.text or "").split()[1:]
    if len(args) == 1:
        group_id = _telegram_id(args[0], group=True)
    elif not args and message.chat.type in {"group", "supergroup"}:
        group_id = _telegram_id(str(message.chat.id), group=True)
    else:
        group_id = None
    if group_id is None:
        _permission_reply(message, f"Usa /{command} en el grupo o /{command} seguido de su ID negativo.")
        return
    allowed = command == "permitirgrupo"
    try:
        changed = set_chat_permission(group_id, allowed)
    except (OSError, ValueError):
        _permission_reply(message, "No se pudo guardar el permiso del grupo.")
        return

    if allowed:
        result = "Grupo autorizado." if changed else "El grupo ya estaba en la lista de permitidos."
    else:
        result = "Permiso de grupo retirado." if changed else "El grupo no estaba en la lista de permitidos."
    if current_settings.allow_all_groups:
        result += " El modo de todos los grupos sigue activo."
    _permission_reply(message, result)


@bot.message_handler(commands=["privados"])
def manage_private_permissions(message):
    from spdecode.runtime import set_chat_permission, settings as current_settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    args = (message.text or "").split()[1:]
    if not is_admin(user_id, current_settings):
        if args:
            _permission_reply(message, "Solo los administradores de SP-DECODE pueden gestionar estos permisos.")
        else:
            allowed = can_use_private_chat(user_id, current_settings)
            _permission_reply(message, "Tu cuenta tiene acceso al bot por privado." if allowed else
                              "Tu cuenta necesita autorización para usar el bot por privado.")
        return

    if not args:
        admins = ", ".join(map(str, sorted(current_settings.admins))) or "Ninguno"
        users = ", ".join(map(str, sorted(current_settings.allowed_private_users - current_settings.admins))) or "Ninguno"
        _send_html_parts(
            message.chat.id,
            f"<b>Acceso al chat privado</b>\nAdministradores: {admins}\nUsuarios autorizados: {users}\n\n"
            "/privados permitir ID · /privados revocar ID",
            reply_to_message_id=message.message_id,
            **thread_options(message),
        )
        return

    target = _telegram_id(args[1], group=False) if len(args) == 2 else None
    if target is None or args[0] not in {"permitir", "revocar"}:
        _permission_reply(message, "Usa /privados permitir ID o /privados revocar ID con un ID de usuario positivo.")
        return
    if is_admin(target, current_settings):
        _permission_reply(message, "Ese usuario tiene acceso por su rol de administrador.")
        return
    allowed = args[0] == "permitir"
    try:
        changed = set_chat_permission(target, allowed)
    except (OSError, ValueError):
        _permission_reply(message, "No se pudo guardar el permiso de chat privado.")
        return

    if allowed:
        result = "Usuario autorizado por privado." if changed else "El usuario ya tenía autorización por privado."
    else:
        result = "Permiso de chat privado retirado." if changed else "El usuario no tenía permiso de chat privado."
    _permission_reply(message, result)


@bot.message_handler(commands=["ping"])
def ping(message):
    bot.reply_to(
        message,
        "<b>SP-DECODE operativo</b>\nEl bot está recibiendo y procesando mensajes.",
        parse_mode="HTML",
    )


@bot.message_handler(commands=["status"])
def show_status(message):
    from spdecode.runtime import settings

    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if not is_admin(user_id, settings):
        bot.reply_to(
            message,
            "<b>Acceso restringido</b>\nEste comando está disponible solo para administradores.",
            parse_mode="HTML",
        )
        return

    session = get_session(message, settings.text_session_timeout_seconds)
    session_status = _protocol_label(session.protocol) if session is not None else "ninguna"
    group_access = (
        "todos los grupos y supergrupos"
        if settings.allow_all_groups
        else f"{len(settings.allowed_groups)} grupo(s) seleccionado(s)"
    )
    bot.reply_to(
        message,
        "<b>Estado de SP-DECODE</b>\n"
        "Estado: <b>activo</b>\n"
        f"Administradores: <b>{len(settings.admins)}</b>\n"
        f"Acceso de grupos: <b>{html_pre(group_access)}</b>\n"
        f"Usuarios de chat privado autorizados: <b>{len(settings.allowed_private_users)}</b>\n"
        f"Decodificadores registrados: <b>{len(FILE_FORMATS)}</b>\n"
        f"Sesión multipart para este usuario/chat: <b>{html_pre(session_status)}</b>\n"
        f"Timeout de decodificadores: <b>{settings.decoder_timeout_seconds}s</b>",
        parse_mode="HTML",
    )


@bot.message_handler(commands=["about"])
def about(message):
    bot.reply_to(
        message,
        "<b>SP-DECODE</b>\n"
        "Bot modular para procesar configuraciones mediante decodificadores Python, Node.js y PHP.\n\n"
        "Desarrollador: @Gh0stDeveloper\n"
        "Canal: @GhostDeve\n"
        "Grupo: @CodeBreakersHub",
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
