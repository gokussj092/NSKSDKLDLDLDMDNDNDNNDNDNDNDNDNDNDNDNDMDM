"""Remember the groups where the bot receives activity (for /groups).

This handler runs first and never consumes the message: it records the
group and lets the dispatcher continue to the real handler.
"""
from __future__ import annotations

import logging

from telebot.handler_backends import ContinueHandling

from spdecode.runtime import bot, record_known_group

logger = logging.getLogger("sp-decode")

_GROUP_CONTENT_TYPES = [
    "text", "audio", "document", "photo", "sticker", "video", "video_note",
    "voice", "location", "contact", "poll", "dice", "game", "invoice",
    "new_chat_members", "left_chat_member", "new_chat_title", "new_chat_photo",
    "delete_chat_photo", "pinned_message", "video_chat_started",
    "video_chat_ended", "successful_payment", "web_app_data", "connected_website",
]


@bot.message_handler(chat_types=["group", "supergroup"], content_types=_GROUP_CONTENT_TYPES)
def record_group_activity(message):
    try:
        chat = getattr(message, "chat", None)
        chat_id = getattr(chat, "id", None)
        title = getattr(chat, "title", None)
        if type(chat_id) is int:
            record_known_group(chat_id, title)
    except Exception:
        logger.debug("Could not record the group", exc_info=True)
    return ContinueHandling()
