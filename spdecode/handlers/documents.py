from __future__ import annotations

import logging

from cloud.workers.python.engine import MAX_INPUT_BYTES
from spdecode.access import require_authorized
from spdecode.decoder_runtime import file_suffix
from spdecode.handlers.decoder_credentials import decode_and_reply
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot, settings
from spdecode.utils import clean_filename

logger = logging.getLogger("sp-decode")


@bot.message_handler(content_types=["document"])
@require_authorized("Files")
def process_received_file(message):
    document = message.document
    if document is None:
        return

    size_limit = min(settings.max_file_size_bytes, MAX_INPUT_BYTES)
    if (getattr(document, "file_size", 0) or 0) > size_limit:
        bot.reply_to(message, f"The file exceeds the {size_limit // (1024 * 1024)} MB limit.")
        return

    file_name = clean_filename(document.file_name or "file")
    suffix = file_suffix(file_name)
    if suffix is None:
        bot.reply_to(message, "Unsupported file format. Use /formats to see the supported formats.")
        return

    try:
        file_info = bot.get_file(document.file_id)
        payload = bot.download_file(file_info.file_path)
    except Exception as error:
        logger.warning("Could not download the Telegram document (%s)", type(error).__name__)
        bot.reply_to(message, "Could not download the file from Telegram.")
        return
    if len(payload) > size_limit:
        bot.reply_to(message, f"The file exceeds the {size_limit // (1024 * 1024)} MB limit.")
        return

    decode_and_reply(
        message,
        payload,
        suffix=suffix,
        deliver=lambda result: send_markdown_result(
            message, f".{suffix}", result.text, source_file=file_name, partial=result.partial,
        ),
    )
