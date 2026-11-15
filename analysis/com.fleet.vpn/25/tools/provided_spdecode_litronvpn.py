#!/usr/bin/env python3
"""SP-DECODE | LitronVPN catalog downloader and decoder.

I made this script to download the catalog, decode its original format,
and save the complete JSON

It works on Termux and regular Python installations. If the file already
exists, I replace it with the new verified result automatically.

Credits:
    Developer: @Gh0stDeveloper
    Channel:   @GhostDeve
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


SOURCE = "https://godtechprime.github.io/latestv2ray.txt"
ALPHABET_B64 = "4oCA4oCB4oCC4oCD4oCE4oCF4oCG4oCH4oCI4oCJ4oCK4oCL4oCM4oCN4oCO4oCP"
APP_KEY = "godtech25"
INITIAL_VECTOR = bytes(16)
FILE_NAME = "litronvpn_catalog.json"
MAX_DOWNLOAD_BYTES = 5 * 1024 * 1024
_INTERNAL_MARKER = (
    "46463a39442d2c2a262d2c6346462b1049292e01591a1d2d0c1f0c0506190c1b"
    "6346462a010807070c0553292e01061a1d2d0c1f0c"
)


class CatalogError(Exception):
    """I use this for safe, readable errors without exposing source details."""


def _display_lines() -> list[str]:
    # I restore the visible labels only when I need to insert them in JSON.
    return bytes(x ^ 0x69 for x in bytes.fromhex(_INTERNAL_MARKER)).decode("utf-8").splitlines()


def _load_crypto() -> tuple[Any, Any, Any]:
    # I first check whether the required AES library is already installed.
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        return AES, pad, unpad
    except ImportError:
        pass

    # If it is missing, I try to install it automatically. The pip output
    # stays hidden so it does not flood the screen with unnecessary details.
    print("[SP-DECODE] Installing the required dependency...")
    commands = (
        [sys.executable, "-m", "pip", "install", "--quiet", "pycryptodome"],
        [sys.executable, "-m", "pip", "install", "--quiet", "--user", "pycryptodome"],
    )
    for command in commands:
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=120,
            )
            if completed.returncode != 0:
                continue
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            return AES, pad, unpad
        except (OSError, subprocess.TimeoutExpired, ImportError):
            continue

    raise CatalogError(
        "The AES dependency could not be installed. "
        "Run: python -m pip install pycryptodome"
    )


def _aes_key() -> bytes:
    # I keep the same key derivation used by the original catalog format.
    # Changing it would make the downloaded data impossible to decrypt.
    encoded_key = APP_KEY.encode("utf-8").hex().upper().encode("ascii")
    return hashlib.sha256(encoded_key).digest()


def _default_path() -> Path:
    # On Termux I use Android Downloads; on other systems I use Documents.
    android_downloads = Path.home() / "storage" / "downloads"
    if android_downloads.is_dir():
        return android_downloads / FILE_NAME
    return Path.home() / "Documents" / FILE_NAME


def _output_path(value: str | None) -> Path:
    if value is None:
        return _default_path()
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if value.endswith(("/", os.sep)) or path.is_dir():
        return path / FILE_NAME
    return path


def _download(timeout: float, max_bytes: int) -> bytes:
    # I never print the download URL. I also reject an unexpected redirect.
    request = Request(SOURCE, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "godtechprime.github.io":
                raise CatalogError("The catalog download was redirected unexpectedly.")
            if response.status != 200:
                raise CatalogError(f"Catalog download failed (HTTP {response.status}).")

            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > max_bytes:
                        raise CatalogError("The catalog is larger than the allowed limit.")
                except ValueError as exc:
                    raise CatalogError("The server returned an invalid response size.") from exc

            # I read a limited number of bytes even if the server does not
            # include a Content-Length header.
            result = response.read(max_bytes + 1)
    except HTTPError as exc:
        raise CatalogError(f"Catalog download failed (HTTP {exc.code}).") from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise CatalogError("Could not connect to the catalog server.") from exc

    if not result:
        raise CatalogError("The downloaded catalog is empty.")
    if len(result) > max_bytes:
        raise CatalogError("The catalog is larger than the allowed limit.")
    return result


def _decode_catalog(raw: bytes, AES: Any, pad: Any, unpad: Any, key: bytes) -> dict[str, Any]:
    # This catalog uses 16 special Unicode characters in place of hex digits.
    # I restore the original bytes first, then Base64, then AES-CBC.
    try:
        source = raw.decode("utf-8")
        alphabet = base64.b64decode(ALPHABET_B64, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise CatalogError("The catalog has an unsupported encoding.") from exc

    if len(alphabet) != 16 or len(set(alphabet)) != 16:
        raise CatalogError("The catalog alphabet is invalid.")
    if not source or len(source) % 2:
        raise CatalogError("The encoded catalog is incomplete.")

    table = {char: i for i, char in enumerate(alphabet)}
    try:
        numbers = [table[char] for char in source]
    except KeyError as exc:
        raise CatalogError("The catalog contains an unexpected symbol.") from exc

    wrapped = bytes((numbers[i] << 4) | numbers[i + 1] for i in range(0, len(numbers), 2))
    try:
        ciphertext = base64.b64decode(wrapped, validate=True)
        decrypted = AES.new(key, AES.MODE_CBC, INITIAL_VECTOR).decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)
    except (ValueError, binascii.Error) as exc:
        raise CatalogError("The catalog could not be decrypted.") from exc

    # I verify that encryption reproduces the exact original payload.
    # Some of these Unicode characters are spaces, so I must NOT strip them.
    check = AES.new(key, AES.MODE_CBC, INITIAL_VECTOR).encrypt(pad(plaintext, AES.block_size))
    check_b64 = base64.b64encode(check)
    restored = "".join(alphabet[b >> 4] + alphabet[b & 15] for b in check_b64)
    if restored != source:
        raise CatalogError("Catalog integrity verification failed.")

    try:
        document = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError("The decrypted catalog is not valid JSON.") from exc

    if not isinstance(document, dict):
        raise CatalogError("The catalog must contain a JSON object.")
    if not all(field in document for field in ("Version", "Networks", "Servers")):
        raise CatalogError("The catalog is missing its required sections.")
    if not isinstance(document["Networks"], list) or not isinstance(document["Servers"], list):
        raise CatalogError("The catalog sections have an unexpected format.")
    return document


def _decode_hidden(value: str, AES: Any, unpad: Any, key: bytes) -> str:
    # Some fields are stored as invisible Unicode symbols. I only try to
    # decode strings made entirely of those symbols, leaving normal text alone.
    if not value or not all("\u2000" <= char <= "\u200f" for char in value):
        return value
    try:
        raw = bytes.fromhex("".join(f"{ord(char) - 0x2000:X}" for char in value))
    except ValueError:
        return value

    # I check both formats used by these fields: Base64-wrapped AES and raw AES.
    candidates = [raw]
    try:
        candidates.insert(0, base64.b64decode(raw, validate=True))
    except (ValueError, binascii.Error):
        pass

    for candidate in candidates:
        if not candidate or len(candidate) % AES.block_size:
            continue
        try:
            decrypted = AES.new(key, AES.MODE_CBC, INITIAL_VECTOR).decrypt(candidate)
            return unpad(decrypted, AES.block_size).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue

    # If a value is only hidden plain text, I restore it without inventing
    # any replacement. If it is unknown, I leave the original untouched.
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return value


def _walk(document: Any, AES: Any, unpad: Any, key: bytes) -> Any:
    # I go through the full structure so nested servers and lists are included.
    if isinstance(document, dict):
        return {name: _walk(value, AES, unpad, key) for name, value in document.items()}
    if isinstance(document, list):
        return [_walk(item, AES, unpad, key) for item in document]
    if isinstance(document, str):
        return _decode_hidden(document, AES, unpad, key)
    return document


def _prepare_json(document: dict[str, Any]) -> bytes:
    decorated = {line: "" for line in _display_lines()}
    decorated.update(document)
    return (json.dumps(decorated, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _save_and_verify(destination: Path, data: bytes) -> None:
    # I always replace an existing result instead of asking for --force.
    # A temporary file ensures I never leave a half-written JSON behind.
    if destination.is_symlink() or destination.is_dir():
        raise CatalogError("The output location is not a safe regular file path.")

    try:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    except OSError as exc:
        raise CatalogError("Could not prepare the output directory.") from exc

    temp_file = Path(name)
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

        if destination.is_symlink() or destination.is_dir():
            raise CatalogError("The destination changed to an unsafe file path.")
        os.replace(temp_file, destination)

        if os.name != "nt":
            try:
                destination.chmod(0o600)
            except OSError:
                pass

        # I read the result back, because a successful write alone is not
        # enough to guarantee the file contains the complete output.
        with destination.open("rb") as saved:
            digest = hashlib.sha256(saved.read()).digest()
        if digest != hashlib.sha256(data).digest():
            raise CatalogError("The saved file did not pass verification.")
    except OSError as exc:
        raise CatalogError("Could not write or verify the output file.") from exc
    finally:
        try:
            temp_file.unlink(missing_ok=True)
        except OSError:
            pass


def _index_android_file(destination: Path) -> None:
    # On Termux this lets Android discover the new download if supported.
    scanner = shutil.which("termux-media-scan")
    if scanner:
        try:
            subprocess.run(
                [scanner, str(destination)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False, timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SP-DECODE: download, decode and save the LitronVPN catalog."
    )
    parser.add_argument("-o", "--output", help="destination file or directory")
    parser.add_argument("--timeout", type=float, default=30.0, help="connection timeout in seconds")
    parser.add_argument("--max-bytes", type=int, default=MAX_DOWNLOAD_BYTES, help="maximum download size")
    parser.add_argument("--no-media-scan", action="store_true", help="skip Android media indexing")
    parser.add_argument("--force", action="store_true", help=argparse.SUPPRESS)  # Legacy flag.
    args = parser.parse_args()

    if not (0 < args.timeout < float("inf")):
        parser.error("--timeout must be a positive finite number")
    if args.max_bytes <= 0:
        parser.error("--max-bytes must be a positive number")

    destination = _output_path(args.output)
    try:
        AES, pad, unpad = _load_crypto()
        key = _aes_key()
        print("[SP-DECODE] Downloading catalog...")
        raw = _download(args.timeout, args.max_bytes)
        print("[SP-DECODE] Decoding catalog...")
        document = _decode_catalog(raw, AES, pad, unpad, key)
        decoded = _walk(document, AES, unpad, key)
        content = _prepare_json(decoded)
        _save_and_verify(destination, content)
    except CatalogError as exc:
        parser.exit(1, f"[SP-DECODE] Error: {exc}\n")

    if not args.no_media_scan:
        _index_android_file(destination)

    print("[SP-DECODE] Catalog saved and verified successfully.")
    print(f"[SP-DECODE] File: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
