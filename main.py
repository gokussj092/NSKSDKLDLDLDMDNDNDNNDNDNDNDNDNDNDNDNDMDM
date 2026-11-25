from __future__ import annotations

import logging
import time
from pathlib import Path

# El orden de importación conserva la prioridad de los handlers específicos.
from spdecode.handlers import decoder_credentials as _decoder_credentials  # noqa: F401
from spdecode.handlers import commands as _commands  # noqa: F401
from spdecode.handlers import cloud_texts as _cloud_texts  # noqa: F401
from spdecode.handlers import extra_text_protocols as _extra_text_protocols  # noqa: F401
from spdecode.handlers import text_protocols as _text_protocols  # noqa: F401
from spdecode.handlers import config_batch_texts as _config_batch_texts  # noqa: F401
from spdecode.handlers import documents as _documents  # noqa: F401
from spdecode.handlers import fallback as _fallback  # noqa: F401
from spdecode.decoder_runtime import FILE_FORMATS
from spdecode.registry import validate_decoder_files
from spdecode.runtime import bot, settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("sp-decode")


def print_banner() -> None:
    print("=" * 50)
    print(f"{'SP-DECODE BOT ONLINE':^50}")
    print("=" * 50)
    print(f"{'Developer:':<18} @Gh0stDeveloper")
    print(f"{'Telegram channel:':<18} https://t.me/GhostDeve")
    print(f"{'Website:':<18} https://GhostDeveloper.vercel.app")
    print(f"{'Admins:':<18} {len(settings.admins)}")
    group_mode = "all groups" if settings.allow_all_groups else str(len(settings.allowed_groups))
    print(f"{'Group access:':<18} {group_mode}")
    print(f"{'Decoders:':<18} {len(FILE_FORMATS)}")
    print("=" * 50)


def validate_startup() -> None:
    errors = validate_decoder_files()
    errors.extend(
        f".{suffix}: shared decoder not found"
        for suffix, item in FILE_FORMATS.items()
        if not Path(item["source"]).is_file()
    )
    if errors:
        formatted = "\n".join(f" - {error}" for error in errors)
        raise RuntimeError(f"Invalid decoder registry:\n{formatted}")


def run_bot() -> None:
    validate_startup()
    _commands.configure_bot_commands()
    print_banner()
    while True:
        try:
            logger.info("Starting Telegram long polling...")
            bot.infinity_polling(
                timeout=30,
                long_polling_timeout=30,
                skip_pending=True,
            )
        except KeyboardInterrupt:
            logger.info("Bot stopped by the user.")
            break
        except Exception:
            logger.exception("Polling interrupted. Retrying in 5 seconds.")
            time.sleep(5)


if __name__ == "__main__":
    run_bot()
