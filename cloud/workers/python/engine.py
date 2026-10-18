#!/usr/bin/env python3
"""C2 file-engine adapter: isolated subprocess, canonical C0 map, no bot imports.

No arbitrary script paths or runtime names are accepted from requests.
Input and output stay in a private temporary directory and are never logged.
"""
from __future__ import annotations

import base64
import csv
from functools import partial
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
MATRIX = ROOT / "docs/cloud/C0_FORMAT_MATRIX.csv"
DECODERS = (ROOT / "decoders").resolve()
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 20
# NUR server lists contain many independently Argon2id-protected fields.
# A dedicated budget must not weaken the 20-second cap of other decoders.
CATALOG_TIMEOUT_SECONDS = 120
_ALLOWED_RUNTIMES = frozenset({"python", "node", "php"})


class DecodeFailure(Exception):
    """A sanitized error is safe to share with a caller."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def load_file_engines() -> dict[str, dict[str, str]]:
    with MATRIX.open("r", encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 240 or len({item["suffix"] for item in rows}) != 240:
        raise RuntimeError("Invalid frozen C0 inventory")
    engines = {}
    for item in rows:
        suffix = item["suffix"]
        script = item["source_script"]
        runtime = item["source_runtime"]
        source = (ROOT / script).resolve()
        if (
            runtime not in _ALLOWED_RUNTIMES
            or not source.is_relative_to(DECODERS)
            or not source.is_file()
            or not suffix
            or "/" in suffix
            or "\\" in suffix
        ):
            raise RuntimeError("Invalid frozen C0 engine mapping")
        engines[suffix] = {
            "source": str(source),
            "runtime": runtime,
            "name": item["app_name"],
            "phase": item["android_phase"],
        }
    return engines


def _child_limits(cpu_budget: int = TIMEOUT_SECONDS) -> None:
    """POSIX resource caps on untrusted decoder subprocesses."""
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_budget + 2, cpu_budget + 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES + 1, MAX_OUTPUT_BYTES + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _child_env(private_dir: str) -> dict[str, str]:
    # Never leak worker token or web/db secrets to individual decoder engines.
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "PYTHONPATH": str(ROOT),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": private_dir,
        "TMPDIR": private_dir,
        "PYTHONDONTWRITEBYTECODE": "1",
        "NODE_ENV": "production",
    }


def decode_file(suffix: str, contents: bytes, *, timeout: int = TIMEOUT_SECONDS, credentials: dict | None = None) -> dict:
    """Execute one canonical file engine. The caller must authenticate first."""
    if not isinstance(suffix, str) or suffix not in load_file_engines():
        raise DecodeFailure("UNSUPPORTED_FORMAT")
    if not isinstance(contents, bytes) or not contents:
        raise DecodeFailure("INVALID_INPUT")
    if len(contents) > MAX_INPUT_BYTES:
        raise DecodeFailure("INPUT_TOO_LARGE")
    if not isinstance(timeout, int) or timeout < 1 or timeout > TIMEOUT_SECONDS:
        raise DecodeFailure("INVALID_REQUEST")
    engine = load_file_engines()[suffix]
    if credentials is not None:
        if suffix != "hc" or not isinstance(credentials, dict) or set(credentials) - {"password", "hwid"}:
            raise DecodeFailure("CREDENTIALS_NOT_ALLOWED")
        for name, maximum in (("password", 4096), ("hwid", 128)):
            value = credentials.get(name)
            if value is not None and (not isinstance(value, str) or not 0 < len(value) <= maximum):
                raise DecodeFailure("INVALID_CREDENTIALS")
    # HTTP Custom must also inspect HCCFG locks without sending passwords in
    # command arguments. All other suffixes use their original script unchanged.
    protected_hc = suffix == "hc"
    source = str(Path(__file__).with_name("hc_bridge.py")) if protected_hc else engine["source"]
    runtime = sys.executable if protected_hc or engine["runtime"] == "python" else shutil.which(engine["runtime"])
    if not runtime:
        raise DecodeFailure("ENGINE_UNAVAILABLE")

    with tempfile.TemporaryDirectory(prefix="spdecode-c2-") as folder:
        input_file = Path(folder) / ("input." + suffix)
        output_file = Path(folder) / "stdout"
        input_file.write_bytes(contents)
        input_file.chmod(0o600)
        with output_file.open("wb") as output:
            try:
                proc = subprocess.Popen(
                    [runtime, source, str(input_file)],
                    cwd=ROOT,
                    env=_child_env(folder),
                    stdin=subprocess.PIPE if protected_hc else subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=_child_limits,
                )
            except OSError as error:
                raise DecodeFailure("ENGINE_UNAVAILABLE") from error
            try:
                if protected_hc:
                    proc.communicate(input=json.dumps(credentials or {}).encode("utf-8"), timeout=timeout)
                    returncode = proc.returncode
                else:
                    returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise DecodeFailure("ENGINE_TIMEOUT") from error
        with output_file.open("rb") as stream:
            raw = stream.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise DecodeFailure("OUTPUT_TOO_LARGE")
        if returncode != 0:
            if protected_hc and returncode == 3:
                try:
                    code = json.loads(raw.decode("utf-8")).get("workerError")
                except (UnicodeError, ValueError, AttributeError):
                    code = None
                if code in ("PASSWORD_REQUIRED", "HWID_REQUIRED", "HWID_PASSWORD_REQUIRED", "AUTH_FAILED"):
                    raise DecodeFailure(code)
            raise DecodeFailure("DECODE_FAILED")
        if not raw.strip():
            raise DecodeFailure("DECODE_FAILED")
        try:
            raw_text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise DecodeFailure("OUTPUT_INVALID_UTF8") from error
        structured = None
        try:
            structured = json.loads(raw_text)
        except ValueError:
            pass
        return {
            "apiVersion": "v1",
            "status": "success",
            "format": suffix,
            "decoder": {
                "engine": engine["runtime"],
                "name": engine["name"],
                "phase": engine["phase"],
                "exporterCertified": False,
            },
            # Keep output including trailing newline; no truncation or masking.
            "rawText": raw_text,
            "structuredJson": structured,
            "isPartial": False,
            "warnings": [],
        }


def decode_b64(suffix: str, encoded: str) -> dict:
    """Base64 strictly decoded; no unrelated extension/key fallback."""
    if not isinstance(encoded, str) or len(encoded) > ((MAX_INPUT_BYTES + 2) // 3) * 4:
        raise DecodeFailure("INPUT_TOO_LARGE")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise DecodeFailure("INVALID_BASE64") from error
    return decode_file(suffix, payload)


def decode_text(text: str, *, timeout: int = TIMEOUT_SECONDS) -> dict:
    """Run the dedicated source-derived text bridge in its own limited process."""
    if not isinstance(text, str) or not text.strip() or len(text) > 250_000:
        raise DecodeFailure("INVALID_INPUT")
    if not isinstance(timeout, int) or timeout < 1 or timeout > TIMEOUT_SECONDS:
        raise DecodeFailure("INVALID_REQUEST")
    bridge = Path(__file__).with_name("text_bridge.py")
    if not bridge.is_file():
        raise DecodeFailure("ENGINE_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="spdecode-c2-text-") as folder:
        input_path = Path(folder) / "input.txt"
        output_path = Path(folder) / "stdout"
        input_path.write_text(text, encoding="utf-8")
        input_path.chmod(0o600)
        with output_path.open("wb") as output:
            try:
                proc = subprocess.Popen(
                    [sys.executable, str(bridge), str(input_path)],
                    cwd=ROOT,
                    env=_child_env(folder),
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=_child_limits,
                )
            except OSError as error:
                raise DecodeFailure("ENGINE_UNAVAILABLE") from error
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise DecodeFailure("ENGINE_TIMEOUT") from error
        with output_path.open("rb") as stream:
            raw = stream.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise DecodeFailure("OUTPUT_TOO_LARGE")
        if returncode != 0 or not raw.strip():
            raise DecodeFailure("DECODE_FAILED")
        try:
            raw_text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise DecodeFailure("OUTPUT_INVALID_UTF8") from error
        try:
            structured = json.loads(raw_text)
        except ValueError:
            structured = None
        return {
            "apiVersion": "v1",
            "status": "success",
            "kind": "text",
            "rawText": raw_text,
            "structuredJson": structured,
            "isPartial": False,
            "warnings": [],
            "exporterCertified": False,
        }


def decode_catalog(contents: bytes, *, timeout: int = CATALOG_TIMEOUT_SECONDS) -> dict:
    """NUR server catalog: authenticated input bytes, no URL fetching."""
    if not isinstance(contents, bytes) or not contents:
        raise DecodeFailure("INVALID_INPUT")
    if len(contents) > MAX_INPUT_BYTES:
        raise DecodeFailure("INPUT_TOO_LARGE")
    if not isinstance(timeout,int) or not 1 <= timeout <= CATALOG_TIMEOUT_SECONDS:
        raise DecodeFailure("INVALID_REQUEST")
    bridge = Path(__file__).with_name("catalog_bridge.py")
    if not bridge.is_file():
        raise DecodeFailure("ENGINE_UNAVAILABLE")
    with tempfile.TemporaryDirectory(prefix="spdecode-c2-catalog-") as folder:
        source = Path(folder) / "catalog.enc"
        output_file = Path(folder) / "stdout"
        source.write_bytes(contents)
        source.chmod(0o600)
        with output_file.open("wb") as output:
            try:
                proc = subprocess.Popen(
                    [sys.executable, str(bridge), str(source)],
                    cwd=ROOT, env=_child_env(folder), stdin=subprocess.DEVNULL,
                    stdout=output, stderr=subprocess.DEVNULL,
                    close_fds=True, start_new_session=True, preexec_fn=partial(_child_limits,CATALOG_TIMEOUT_SECONDS),
                )
            except OSError as error:
                raise DecodeFailure("ENGINE_UNAVAILABLE") from error
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise DecodeFailure("ENGINE_TIMEOUT") from error
        if rc != 0:
            raise DecodeFailure("DECODE_FAILED")
        with output_file.open("rb") as stream:
            raw = stream.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise DecodeFailure("OUTPUT_TOO_LARGE")
        try:
            text = raw.decode("utf-8")
            structured = json.loads(text)
        except (ValueError, UnicodeError) as error:
            raise DecodeFailure("OUTPUT_INVALID") from error
        return {
            "apiVersion": "v1", "status": "success", "kind": "nur_catalog",
            "rawText": text, "structuredJson": structured,
            "isPartial": False, "warnings": [], "exporterCertified": False,
        }
