from __future__ import annotations

import logging
from io import BytesIO

from cloud.workers.python.engine import MAX_INPUT_BYTES
from spdecode.access import require_authorized
from spdecode.decoder_runtime import DecodeResult, file_suffix
from spdecode.handlers.decoder_credentials import decode_and_reply
from spdecode.runtime import bot, settings
from spdecode.utils import clean_filename, html_pre, thread_options

logger = logging.getLogger("sp-decode")


def send_decoder_output(message, result: DecodeResult, *, caption: str, attach: bool = False) -> None:
    topic = thread_options(message)
    if result.partial:
        bot.reply_to(message, "Resultado parcial. El archivo de salida identifica los campos que quedaron sin resolver.", **topic)
        attach = True
    if len(result.text.encode("utf-16-le")) <= 7000:
        bot.reply_to(
            message,
            f"<b>SP-DECODE</b>\n<pre>{html_pre(result.text)}</pre>",
            parse_mode="HTML",
            **topic,
        )
    else:
        attach = True
    if attach:
        with BytesIO(result.text.encode("utf-8")) as output:
            output.name = "spdecode-resultado.txt"
            bot.send_document(
                chat_id=message.chat.id,
                document=output,
                caption=caption,
                reply_to_message_id=message.message_id,
                **topic,
            )


@bot.message_handler(content_types=["document"])
@require_authorized("Los archivos")
def process_received_file(message):
    document = message.document
    if document is None:
        return

    size_limit = min(settings.max_file_size_bytes, MAX_INPUT_BYTES)
    if (getattr(document, "file_size", 0) or 0) > size_limit:
        bot.reply_to(message, f"El archivo supera el límite de {size_limit // (1024 * 1024)} MB.")
        return

    file_name = clean_filename(document.file_name or "archivo")
    suffix = file_suffix(file_name)
    if suffix is None:
        bot.reply_to(message, "Formato no soportado. Usa /formats para consultar los formatos disponibles.")
        return

    try:
        file_info = bot.get_file(document.file_id)
        payload = bot.download_file(file_info.file_path)
    except Exception as error:
        logger.warning("No se pudo descargar el documento de Telegram (%s)", type(error).__name__)
        bot.reply_to(message, "No se pudo descargar el archivo de Telegram.")
        return
    if len(payload) > size_limit:
        bot.reply_to(message, f"El archivo supera el límite de {size_limit // (1024 * 1024)} MB.")
        return

    decode_and_reply(
        message,
        payload,
        suffix=suffix,
        deliver=lambda result: send_decoder_output(
            message, result, caption=f"SP-DECODE — {file_name} (.{suffix})", attach=True,
        ),
    )
