"""Local adapter for the same file and text dispatcher used by SP-DECODE Cloud."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from cloud.workers.python import engine
from .config import PROJECT_DIR


FILE_FORMATS = engine.load_runtime_file_engines()
_FILE_SUFFIXES = tuple(sorted(FILE_FORMATS, key=len, reverse=True))
# Multipart sessions and configured local HAPP keys retain their Telegram handlers.
# V2Box text retains its normalization step before opening a password session.
_BOT_TEXT_HANDLERS = {"tls", "ssc", "dark", "happ", "v2box"}
TEXT_FORMATS = {
    item["prefix"]: item["name"]
    for item in json.loads(
        (PROJECT_DIR / "cloud/web/content/text-formats.json").read_text(encoding="utf-8")
    )["formats"]
    if item["kind"] == "text" and item["suffix"] not in _BOT_TEXT_HANDLERS
}
_TEXT_PREFIXES = tuple(sorted(TEXT_FORMATS, key=len, reverse=True))


def file_suffix(filename: str) -> str | None:
    lower = filename.lower()
    return next((suffix for suffix in _FILE_SUFFIXES if lower.endswith("." + suffix)), None)


def text_prefix(text: str) -> str | None:
    lower = text.strip().lower()
    return next((prefix for prefix in _TEXT_PREFIXES if lower.startswith(prefix.lower())), None)


@dataclass(frozen=True, slots=True)
class DecodeResult:
    text: str
    partial: bool = False


def decode(
    payload: bytes,
    *,
    suffix: str | None,
    timeout_seconds: int,
    credentials: dict[str, str] | None = None,
) -> DecodeResult:
    """Keep Cloud's resource-controlled subprocess launcher out of Telegram threads."""
    limit = engine.MAX_INPUT_BYTES if suffix is not None else 250_000 * 4
    if not payload or len(payload) > limit:
        raise engine.DecodeFailure("INPUT_TOO_LARGE" if payload else "INVALID_INPUT")
    if suffix is not None and suffix not in FILE_FORMATS:
        raise engine.DecodeFailure("UNSUPPORTED_FORMAT")

    timeout = min(timeout_seconds, engine.TIMEOUT_SECONDS)
    encoded_credentials = json.dumps(credentials or {}).encode("utf-8")
    if len(encoded_credentials) > 8192:
        raise engine.DecodeFailure("INVALID_CREDENTIALS")
    with TemporaryDirectory(prefix="spdecode-telegram-") as directory:
        path = Path(directory) / "input"
        path.write_bytes(payload)
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": "C.UTF-8",
            "HOME": directory,
            "TMPDIR": directory,
        }
        # The shared engine can try a second historical reader. Each attempt
        # has its own timeout and kills its decoder process group on expiry.
        try:
            result = subprocess.run(
                [sys.executable, "-B", "-m", "spdecode.decoder_runtime",
                 suffix or "-", str(path), str(timeout)],
                input=encoded_credentials,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=PROJECT_DIR,
                env=env,
                timeout=2 * timeout + 10,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise engine.DecodeFailure("ENGINE_TIMEOUT") from error
        except OSError as error:
            raise engine.DecodeFailure("ENGINE_UNAVAILABLE") from error

    try:
        value = json.loads(result.stdout)
        if result.returncode == 0 and isinstance(value["text"], str) and value["text"]:
            return DecodeResult(value["text"], value["partial"] is True)
        if result.returncode == 3 and isinstance(value["error"], str):
            raise engine.DecodeFailure(value["error"])
    except (ValueError, TypeError, KeyError):
        pass
    raise engine.DecodeFailure("ENGINE_UNAVAILABLE")


def _run() -> int:
    suffix, path, timeout = sys.argv[1:]
    raw = Path(path).read_bytes()
    credentials = json.load(sys.stdin) or None
    try:
        if suffix == "-":
            result = engine.decode_text(raw.decode("utf-8"), timeout=int(timeout), credentials=credentials)
        else:
            result = engine.decode_file(
                suffix, raw, timeout=int(timeout), credentials=credentials, full_hat=True,
            )
    except engine.DecodeFailure as error:
        print(json.dumps({"error": error.code}))
        return 3
    print(json.dumps({"text": result["rawText"], "partial": result["isPartial"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(_run())
