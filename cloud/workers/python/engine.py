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
# Provider-specific cap: all other routes retain the existing 4 MiB quota.
MAX_MKK_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_MKK_BUNDLE_BYTES = 45 * 1024 * 1024
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



# C8 additions are separate from the frozen 240-route C0 inventory.
# Keep each format pinned to its own source codec; never route HX .hxt into xor_family.
_C8_FILE_ENGINES = {
    "tx": ("decoders/Python/apps/Tx_Tunnel/file_decoder.py", "Tx Tunnel v2.17"),
    "mmt": ("decoders/Python/apps/MM_Tunnel/file_decoder.py", "MM Tunnel v1.10.11.1"),
    "crev": ("decoders/Python/apps/CREEB_VPN/file_decoder.py", "CREEB VPN 50.0"),
    "creeb": ("decoders/Python/apps/CREEB_INJECTOR/file_decoder.py", "CREEB INJECTOR 38.0"),
    "awg": ("decoders/Python/apps/AboWaged_VPN/file_decoder.py", "AboWaged VPN 1.0"),
    "1ftnl": ("decoders/Python/apps/OneFTunnel/file_decoder.py", "1FTunnel 0.6.99"),
    "tgv": ("decoders/Python/apps/TunelGuard_VPN/file_decoder.py", "TunelGuard VPN 12.8"),
    "rt": ("decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py", "REESE TUNNEL"),
    "gol": ("decoders/Python/apps/VPN_PLUS_PERU/vpn_plus_peru.py", "VPN PLUS PERÚ"),
    "ua": ("decoders/Python/apps/Ultra_Custom/ultra_custom_52.py", "Ultra Custom"),
    "nvpnc": ("decoders/Python/apps/Neutro_VPN/neutro_vpn.py", "Neutro VPN"),
    "green": ("decoders/Python/apps/24clan_VPN_Green/24clan_VPN_Green_archivos.py", "24clan VPN Green"),
    "hxt": ("decoders/Python/apps/HX_Tunnel_VPN/HX_Tunnel_VPN_archivos.py", "HX Tunnel VPN"),
    "mtp": ("decoders/Python/apps/My_Tunnel_Proxy/file_decoder.py", "My Tunnel Proxy"),
    "roy": ("decoders/Python/apps/Royal_Tunnel_VPN/file_decoder.py", "Royal Tunnel VPN 7.0"),
    "aro": ("decoders/Python/apps/AustroPlus_VPN/file_decoder.py", "AustroPlus VPN 13.0.1"),
    "sks": ("decoders/Python/apps/HTTP_FenixVPN/file_decoder.py", "HTTP FenixVPN 19.4 / HTTP Jireh 2.0 / HTTP SocketClay 3.4.0"),
    "tut": ("decoders/Python/apps/Tunneltweak/file_decoder.py", "Tunneltweak 6.2.1"),
    "actun": ("decoders/Python/apps/AC_TUNNEL_VPN/file_decoder.py", "AC TUNNEL VPN 1.4"),
    "4ulite": ("decoders/Python/apps/4U_TUNNEL_LITE/file_decoder.py", "4U TUNNEL LITE"),
}

def load_runtime_file_engines() -> dict[str, dict[str, str]]:
    result = load_file_engines()
    for suffix, (relative, name) in _C8_FILE_ENGINES.items():
        source = (ROOT / relative).resolve()
        if not source.is_relative_to(DECODERS) or not source.is_file():
            raise RuntimeError("C8 engine unavailable")
        result[suffix] = {
            "source": str(source),
            "runtime": "python",
            "name": name,
            "phase": "C8",
        }
    return result

def _child_limits(cpu_budget: int = TIMEOUT_SECONDS, output_bytes: int = MAX_OUTPUT_BYTES) -> None:
    """POSIX resource caps on untrusted decoder subprocesses."""
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_budget + 2, cpu_budget + 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes + 1, output_bytes + 1))
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


def _is_legacy_roy(contents: bytes) -> bool:
    """Old nibble alphabet is disjoint from Royal 7.0's ASCII Base64 wire.

    Dispatch by format, never retry a failed modern decoder with old crypto.
    This keeps the frozen source route usable without coupling the new codec.
    """
    try:
        text = "".join(contents.decode("utf-8-sig").split())
    except UnicodeError:
        return False
    return bool(text) and all(char in "¹²³⁴⁵⁶⁷⁸⁹⁰·,‽:'′" for char in text)


def _is_legacy_aro(contents: bytes) -> bool:
    """Recognize the old complete byte+18 JSON envelope before choosing a codec.

    Both formats use Base64. A valid legacy CONFIG document, rather than an
    AES-GCM failure, selects the frozen route. Never retry a failed GCM codec.
    Translation uses a fixed 256-byte table and input remains worker-bounded.
    """
    try:
        raw = base64.b64decode(b"".join(contents.split()), validate=True)
        shifted = raw.translate(bytes((i + 18) & 255 for i in range(256)))
        value = json.loads(shifted)
        return isinstance(value, dict) and isinstance(value.get("CONFIG"), dict)
    except (ValueError, UnicodeError, RecursionError):
        return False


def _unsupported_npvs_protection(contents: bytes) -> bool:
    """Classify unknown compact versions/methods without rejecting known routes.

    Header inspection does not decrypt data, invent credentials, or infer that
    unrelated corrupt files are protected by a private/public key. Passphrase
    and recipient framing now reach the authenticated NPVS reader.
    """
    if len(contents)<62 or contents[:4]!=b"NPVS" or contents[4] not in (5,6):
        return False
    size=int.from_bytes(contents[5:9],"big")
    if not 135<=size<=262144 or 9+size+80>len(contents):
        return False
    header=contents[9:9+size]
    return header[0]!=1 or header[50] not in (0,1,2)


def decode_file(suffix: str, contents: bytes, *, timeout: int = TIMEOUT_SECONDS, credentials: dict | None = None, full_hat: bool = False) -> dict:
    """Execute one canonical file engine. The caller must authenticate first."""
    if not isinstance(suffix, str) or suffix not in load_runtime_file_engines():
        raise DecodeFailure("UNSUPPORTED_FORMAT")
    if not isinstance(contents, bytes) or not contents:
        raise DecodeFailure("INVALID_INPUT")
    if len(contents) > MAX_INPUT_BYTES:
        raise DecodeFailure("INPUT_TOO_LARGE")
    if not isinstance(timeout, int) or timeout < 1 or timeout > TIMEOUT_SECONDS:
        raise DecodeFailure("INVALID_REQUEST")
    if suffix=="npvs" and _unsupported_npvs_protection(contents):
        raise DecodeFailure("NPVS_PROTECTION_UNSUPPORTED")
    engine = load_runtime_file_engines()[suffix]
    if suffix == "sks":
        # Historical SocksIP exports use a JSON d/v envelope. Fenix imports
        # dot-separated GCM or raw DES. Choose before decryption, never retry
        # after a failed authentication tag in the Fenix reader.
        try:
            historical = json.loads(contents.decode("utf-8-sig"))
            legacy_sks = (isinstance(historical, dict) and
                          isinstance(historical.get("d"), str) and
                          isinstance(historical.get("v"), (str, int)))
        except (ValueError, UnicodeError, RecursionError):
            legacy_sks = False
        if legacy_sks:
            engine = load_file_engines()["sks"]
    if suffix == "hat" and full_hat:
        # Cloud UI requires the complete document. Preserve the original
        # legacy route for frozen C2 reference output parity.
        # Historical hat.js flattens and drops nested configuration fields.
        # The full-result bridge decrypts the same envelope, preserves every
        # original JSON section and decodes known profilev5 values.
        engine = {**engine, "source": str(Path(__file__).with_name("hat_complete.js"))}
    if suffix == "aro" and _is_legacy_aro(contents):
        engine = load_file_engines()["aro"]
    # The APK exports prefixed .actun; keep historical raw RENZ .actun inputs.
    if suffix == "actun":
        try:
            modern = contents.decode("utf-8-sig").strip().startswith("actunnelvpn://")
        except UnicodeError:
            modern = False
        if not modern:
            engine = load_file_engines()["actun"]
    if suffix == "roy" and _is_legacy_roy(contents):
        engine = load_file_engines()["roy"]
    if credentials is not None:
        allowed = {"password", "hwid"} if suffix == "hc" else {"password", "publicKey"} if suffix == "npvs" else {"password"} if suffix in ("tut", "ua", "1ftnl", "v2box") else None
        if allowed is None or not isinstance(credentials, dict) or set(credentials) - allowed:
            raise DecodeFailure("CREDENTIALS_NOT_ALLOWED")
        for name, maximum in (("password", 4096), ("hwid", 128), ("publicKey", 128)):
            value = credentials.get(name)
            if value is not None and (not isinstance(value, str) or not 0 < len(value) <= maximum):
                raise DecodeFailure("INVALID_CREDENTIALS")
            if suffix in ("1ftnl", "npvs") and value is not None:
                try:
                    if len(value.encode("utf-8")) > maximum:
                        raise DecodeFailure("INVALID_CREDENTIALS")
                except UnicodeError as error:
                    raise DecodeFailure("INVALID_CREDENTIALS") from error
    # Protected formats receive credentials on stdin, never argv/env/logs.
    protected_hc = suffix == "hc"
    protected_tut = suffix == "tut"
    protected_ua = suffix == "ua"
    protected_onef = suffix == "1ftnl"
    protected_npvs = suffix == "npvs"
    protected_v2box = suffix == "v2box"
    credential_input = protected_hc or protected_tut or protected_ua or protected_onef or protected_npvs or protected_v2box
    source = engine["source"]
    if protected_hc:
        source = str(Path(__file__).with_name("hc_bridge.py"))
    elif protected_tut or protected_onef:
        source = str(Path(source).with_name("worker_bridge.py"))
    elif protected_ua:
        source = str(Path(__file__).with_name("ultra_custom_bridge.py"))
    elif protected_npvs:
        source = str(Path(__file__).with_name("npvs_bridge.py"))
    elif protected_v2box:
        source = str(Path(__file__).with_name("v2box_bridge.py"))
    runtime = sys.executable if credential_input or engine["runtime"] == "python" else shutil.which(engine["runtime"])
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
                    stdin=subprocess.PIPE if credential_input else subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=_child_limits,
                )
            except OSError as error:
                raise DecodeFailure("ENGINE_UNAVAILABLE") from error
            try:
                if credential_input:
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
            if credential_input and returncode == 3:
                try:
                    code = json.loads(raw.decode("utf-8")).get("workerError")
                except (UnicodeError, ValueError, AttributeError):
                    code = None
                if code in ("PASSWORD_REQUIRED", "HWID_REQUIRED", "HWID_PASSWORD_REQUIRED", "AUTH_FAILED",
                            "PRIVATE_KEY_REQUIRED", "RECIPIENT_MISMATCH", "INVALID_CREDENTIALS",
                            "INVALID_INPUT", "UNSUPPORTED_VERSION", "UNSUPPORTED_METHOD",
                            "UNSUPPORTED_VARIANT", "NPVS_PROTECTION_UNSUPPORTED",
                            "NPVS_APPKEY_AUTH_FAILED"):
                    # The NPVS decoder authenticates its signed envelope before
                    # opening app-key. A failed recognized app-key is ambiguous:
                    # unsupported exporter/key variant OR altered signed input,
                    # never proof that an ECDH recipient private key is needed.
                    # Android 1.1.19 already has a localized variant notice.
                    if suffix == "npvs" and code == "NPVS_APPKEY_AUTH_FAILED":
                        raise DecodeFailure("UNSUPPORTED_VARIANT")
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


def decode_provider_catalog(provider_id: str, contents: bytes) -> dict:
    """One fixed provider codec, child-isolated; broker performs all network I/O."""
    if provider_id not in ("speicers-pro-vpn", "tx-tunnel", "mm-tunnel", "creeb-vpn", "abowaged-vpn", "7net-vpn", "xhypher-tunnel-pro", "ut-loop-pro-vpn", "turbomx-vpn", "superflash-vpn", "rmp-tunnel-pro", "rjc-tunnel-pro", "proneet-vpn", "onspace-vpn", "mx-tunnel-pro", "megatunnel", "http-internet-infinito", "24clan-green", "hx-tunnel", "mkk-hyper", "my-tunnel-proxy", "robust-tunnel", "royal-tunnel", "trv-tunnel", "4u-tunnel-lite", "ac-tunnel-vpn", "austroplus-vpn", "http-fenixvpn", "http-jireh", "http-socketclay", "http-wakko", "v2ray-tunnel-plus", "eut-vpn", "focus-vpn-cloud", "freedom-vpn", "tunelguard-vpn", "tunneltweak", "ksh-vpn", "dtunnel-mod"):
        raise DecodeFailure("UNSUPPORTED_FORMAT")
    if not isinstance(contents, bytes) or not contents:
        raise DecodeFailure("INVALID_INPUT")
    # MKK source bundle carries four separately encrypted fixed-origin replies
    # encoded in Base64; its envelope may exceed one provider response.
    limit = MAX_MKK_BUNDLE_BYTES if provider_id == "mkk-hyper" else 8 * 1024 * 1024
    if len(contents) > limit:
        raise DecodeFailure("INPUT_TOO_LARGE")
    bridge=Path(__file__).with_name("catalog_vpn_bridge.py")
    with tempfile.TemporaryDirectory(prefix="spdecode-c8-catalog-") as folder:
        source=Path(folder)/"catalog.enc"
        target=Path(folder)/"stdout"
        source.write_bytes(contents)
        source.chmod(0o600)
        try:
            with target.open("wb") as output:
                proc=subprocess.Popen(
                    [sys.executable,str(bridge),provider_id,str(source)],
                    cwd=ROOT,env=_child_env(folder),stdin=subprocess.DEVNULL,
                    stdout=output,stderr=subprocess.DEVNULL,close_fds=True,
                    start_new_session=True,preexec_fn=partial(_child_limits,CATALOG_TIMEOUT_SECONDS,
                                                MAX_MKK_OUTPUT_BYTES if provider_id=="mkk-hyper"
                                                else MAX_OUTPUT_BYTES),
                )
                try:
                    rc=proc.wait(timeout=CATALOG_TIMEOUT_SECONDS)
                except subprocess.TimeoutExpired as error:
                    os.killpg(proc.pid,signal.SIGKILL)
                    proc.wait()
                    raise DecodeFailure("ENGINE_TIMEOUT") from error
        except OSError as error:
            raise DecodeFailure("ENGINE_UNAVAILABLE") from error
        if rc!=0:
            if provider_id=="mkk-hyper" and rc==3:
                try:
                    marker=json.loads(target.read_bytes()[:256])
                    if marker.get("workerError")=="OUTPUT_TOO_LARGE":
                        raise DecodeFailure("OUTPUT_TOO_LARGE")
                except (ValueError, UnicodeError, AttributeError):
                    pass
            raise DecodeFailure("DECODE_FAILED")
        output_limit=MAX_MKK_OUTPUT_BYTES if provider_id=="mkk-hyper" else MAX_OUTPUT_BYTES
        with target.open("rb") as result:
            raw=result.read(output_limit+1)
        if len(raw)>output_limit:
            raise DecodeFailure("OUTPUT_TOO_LARGE")
        try:
            raw_text=raw.decode("utf-8")
            structured=json.loads(raw_text)
            if not isinstance(structured,(dict,list)) or not structured:
                raise ValueError("invalid")
        except (ValueError,UnicodeError) as error:
            raise DecodeFailure("OUTPUT_INVALID") from error
        return {
            "apiVersion":"v1","status":"success","kind":"vpn_catalog",
            "providerId":provider_id,"rawText":raw_text,
            "structuredJson":structured,
            "isPartial":provider_id=="mkk-hyper" and isinstance(structured,dict) and structured.get("complete") is False,
            "warnings":["PARTIAL_SOURCE_FAILURE"] if provider_id=="mkk-hyper" and isinstance(structured,dict) and structured.get("complete") is False else [],
            "exporterCertified":False,
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


def decode_text(text: str, *, timeout: int = TIMEOUT_SECONDS, credentials: dict | None = None) -> dict:
    """Run the dedicated source-derived text bridge in its own limited process."""
    if not isinstance(text, str) or not text.strip() or len(text) > 250_000:
        raise DecodeFailure("INVALID_INPUT")
    if not isinstance(timeout, int) or timeout < 1 or timeout > TIMEOUT_SECONDS:
        raise DecodeFailure("INVALID_REQUEST")
    if credentials is not None:
        if (not isinstance(credentials, dict) or set(credentials) != {"password"} or
                not (text.strip().lower().startswith("ua://") or text.strip().startswith(
                    ("1FTnl.", "1FT1.", "1ftunnel://1FTnl/", "1ftunnel://1FT1/")) or
                    any(text.strip().lower().startswith(prefix) and
                        len(text.strip()) > len(prefix) for prefix in
                        ("npvt://", "npvt-ssh://", "npvt-vless://", "npvt-vmess://", "npv://"))) or
                not isinstance(credentials["password"], str) or
                not 0 < len(credentials["password"].encode("utf-8")) <= 4096):
            raise DecodeFailure("INVALID_CREDENTIALS")
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
                    stdin=subprocess.PIPE,
                    stdout=output,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    preexec_fn=_child_limits,
                )
            except OSError as error:
                raise DecodeFailure("ENGINE_UNAVAILABLE") from error
            try:
                proc.communicate(input=json.dumps(credentials or {}).encode("utf-8"), timeout=timeout)
                returncode = proc.returncode
            except subprocess.TimeoutExpired as error:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise DecodeFailure("ENGINE_TIMEOUT") from error
        with output_path.open("rb") as stream:
            raw = stream.read(MAX_OUTPUT_BYTES + 1)
        if len(raw) > MAX_OUTPUT_BYTES:
            raise DecodeFailure("OUTPUT_TOO_LARGE")
        if returncode == 3:
            try:
                code = json.loads(raw.decode("utf-8")).get("workerError")
            except (UnicodeError, ValueError, AttributeError):
                code = None
            if code in ("PASSWORD_REQUIRED", "AUTH_FAILED", "PRIVATE_KEY_REQUIRED",
                        "RECIPIENT_MISMATCH", "INVALID_CREDENTIALS", "INVALID_INPUT",
                        "UNSUPPORTED_VERSION", "UNSUPPORTED_METHOD", "UNSUPPORTED_VARIANT",
                        "NPVS_PROTECTION_UNSUPPORTED"):
                raise DecodeFailure(code)
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
