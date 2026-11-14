#!/usr/bin/env python3
"""C2 file-engine adapter: isolated subprocess, canonical C0 map, no bot imports.

No arbitrary script paths or runtime names are accepted from requests.
Input and output stay in a private temporary directory and are never logged.
"""
from __future__ import annotations

import base64
import binascii
import csv
from functools import partial
import json
import os
from pathlib import Path
import re
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
    "tnl": ("decoders/Python/apps/OpenTunnel/file_decoder.py", "OpenTunnel 1.1.1 / Tunnel"),
    "hexcm": ("decoders/Python/apps/Hex_Tunnel/file_decoder.py", "Hex Tunnel / HexVPN 1.7.3-Rev"),
    "enaa": ("decoders/Python/apps/Enaa_Tunnel/file_decoder.py", "Enaa Tunnel Enna-1.07"),
    "wolf": ("decoders/Python/apps/Wolf_Custom_VPN/file_decoder.py", "Wolf Custom VPN v2.8.1.2"),
    "v2": ("decoders/Python/apps/MTM_Tunnel_Lite/file_decoder.py", "e-V2Ray / MTM Tunnel Lite"),
    "stp": ("decoders/Python/apps/MNR_TUNNEL_PLUS/file_decoder.py", "MNR TUNNEL PLUS 3.1"),
    "kyz": ("decoders/Python/apps/HTTP_Door/file_decoder.py", "HTTP Door 5.0"),
    "bdnet": ("decoders/Python/apps/BD_NET_VPN/file_decoder.py", "BD NET VPN PrinceBuild111"),
    "aura": ("decoders/Python/apps/Aura_Net_VPN/file_decoder.py", "Aura Net VPN AuraNet_v9"),
    "apnavpn": ("decoders/Python/apps/APNA_VPN/file_decoder.py", "APNA VPN 3.9"),
    "dtk": ("decoders/Python/apps/ANY_VPN/file_decoder.py", "ANY VPN build 40"),
    "tx": ("decoders/Python/apps/Tx_Tunnel/file_decoder.py", "Tx Tunnel v2.17"),
    "mmt": ("decoders/Python/apps/MM_Tunnel/file_decoder.py", "MM Tunnel v1.10.30.2"),
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
    "sks": ("decoders/Python/apps/HTTP_FenixVPN/file_decoder.py", "HTTP FenixVPN 19.4 / HTTP Jireh 2.0 / HTTP SocketClay 3.4.0 / TunnelDOOM VPN 4.2.4–4.3.0"),
    "tut": ("decoders/Python/apps/Tunneltweak/file_decoder.py", "Tunneltweak 6.2.1"),
    "actun": ("decoders/Python/apps/AC_TUNNEL_VPN/file_decoder.py", "AC TUNNEL VPN 1.4"),
    "4ulite": ("decoders/Python/apps/4U_TUNNEL_LITE/file_decoder.py", "4U TUNNEL LITE"),
    # C8 Tier A (2026-11-14 integration): eleven new app file decoders.
    "rev": ("decoders/Python/apps/Hunter_VPN/Hunter_VPN_archivos.py", "Rev Hunter 48"),
    "custom": ("decoders/Python/apps/Hunter_VPN/Hunter_VPN_archivos.py", "Rev Hunter 48"),
    "atnet": ("decoders/Python/apps/AT_NET_VPN/AT_NET_VPN_archivos.py", "AT NET VPN v1.9.28.1"),
    "hamaratnl": ("decoders/Python/apps/HAMARA_TUNNEL_LITE/HAMARA_TUNNEL_LITE_archivos.py", "HAMARA TUNNEL LITE 2.9"),
    "bvv": ("decoders/Python/apps/Binke_Volt/Binke_Volt_archivos.py", "Binke Volt 1.1"),
    "zvn": ("decoders/Python/apps/Zam_VIP_NET/Zam_VIP_NET_archivos.py", "Zam VIP NET 42.0"),
    "reg": ("decoders/Python/apps/REG_Tunnel_VPN/REG_Tunnel_VPN_archivos.py", "REG Tunnel VPN v1.9.28.1"),
    "bccnet": ("decoders/Python/apps/JetRoi/JetRoi_archivos.py", "JetRoi v1.9.28.1"),
    "fat": ("decoders/Python/apps/Fat_Tunnel_Lite/Fat_Tunnel_Lite_archivos.py", "Fat Tunnel Lite V1.12"),
    "rnv": ("decoders/Python/apps/RNV_Tunnel_VPN/RNV_Tunnel_VPN_archivos.py", "RNV Tunnel VPN v1.9.28.1"),
    "rjc": ("decoders/Python/apps/RJC_Tunnel_VPN/RJC_Tunnel_VPN_archivos.py", "RJC Tunnel VPN RJC-19"),
    # C8 family overrides (2026-11-14 integration): the verified app-specific
    # decoder takes priority; the frozen C0 family engine stays as fallback.
    "osp": ("decoders/Python/apps/OSP_Tunnel/OSP_Tunnel_archivos.py", "OSP Tunnel 3.7"),
    "hsome": ("decoders/Python/apps/Handsome_Fast/Handsome_Fast_archivos.py", "Handsome Fast 2.2"),
    "v2box": ("decoders/Python/apps/V2Box/V2Box_archivos.py", "V2Box 6.2.3"),
    "ar": ("decoders/Python/apps/AR_PRO_VPN/AR_PRO_VPN_archivos.py", "AR PRO VPN 1.0"),
    "t20": ("decoders/Python/apps/Marvs_SSH/Marvs_SSH_archivos.py", "Marvs SSH / T20-VPN 1.10.5.3"),
    "ost": ("decoders/Python/apps/Shield_Tunnel/Shield_Tunnel_archivos.py", "Shield Tunnel 1.11.06.1"),
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


# C8 overrides whose frozen C0 family engine stays as a fallback: if the
# specific decoder fails with a plain decode error (never a credential,
# version or protection error), decode_file retries once with the C0 engine.
_C8_GENERIC_FALLBACK = frozenset({"osp", "hsome", "v2box", "ar", "t20", "ost"})


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



def _xhypher_export_in_renamed_file(suffix: str, contents: bytes) -> bool:
    """Recognize an intact Xhypher export in the two observed wrong suffixes.

    This is carrier validation, NOT crypto authentication. Only an exact
    vendor prefix and a complete CBC-length Base64 envelope may change the
    selected engine. The Xhypher decoder must still decrypt and parse JSON.
    Short xhypher:// references are never resolved or fetched here.
    """
    if suffix not in ("hat", "bdnet"):
        return False
    try:
        raw = contents.decode("utf-8-sig").strip()
        marker, separator, body = raw.partition("://")
        if not separator or marker.lower() not in ("xhyphertunnelpro", "xhypher"):
            return False
        carrier = "".join(body.split()).encode("ascii")
    except (UnicodeError, ValueError):
        return False
    if len(carrier) < 64 or len(carrier) % 4:
        return False
    try:
        binary = base64.b64decode(carrier, validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    return len(binary) >= 32 and len(binary) % 16 == 0


def _is_hex_custom_v3(contents: bytes) -> bool:
    """Hex Custom HXS3 v3 container: literal magic plus version byte 3.

    Old Hex Tunnel files are Base64 text; 0x03 is not a Base64 byte, so a
    valid old file can never satisfy both checks. A future container
    version would need its version byte added here.
    """
    return len(contents) >= 74 and contents[:4] == b"HXS3" and contents[4] == 3


def _is_vc_tgv(contents: bytes) -> bool:
    """VC VPN .tgv files are text starting with STGCM2.VC. / STGCM3.VC.

    TunelGuard .tgv files are Base64 text, and '.' is not a Base64 byte,
    so they can never carry this prefix.
    """
    try:
        text = contents.decode("utf-8-sig").strip()
    except UnicodeError:
        return False
    return text.startswith("STGCM2.VC.") or text.startswith("STGCM3.VC.")


def _is_shield_ost(contents: bytes) -> bool:
    """Shield Tunnel .ost files are UTF-8 text: a Base64 envelope of at
    least 44 bytes (salt 16 + nonce 12 + ciphertext + GCM tag 16), or a
    plain JSON document. OUSS .ost files are raw DES-ECB ciphertext bytes,
    which are not valid UTF-8 Base64 text.
    """
    try:
        text = contents.decode("utf-8-sig").strip()
    except UnicodeError:
        return False
    if text.startswith("{"):
        try:
            return isinstance(json.loads(text), dict)
        except ValueError:
            return False
    compact = re.sub(r"[ \t\r\n]", "", text)
    if not compact or len(compact) % 4 == 1:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact):
        return False
    try:
        blob = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(blob) >= 44


def _run_decoder_once(source: str, runtime: str, input_file: Path, output_file: Path, *, folder: str, credentials: dict | None, timeout: int) -> tuple[int, bytes]:
    """Run one decoder subprocess; returns (returncode, raw stdout).

    Raises ENGINE_TIMEOUT / ENGINE_UNAVAILABLE / OUTPUT_TOO_LARGE directly:
    those are resource errors, never a reason to try another engine.
    """
    with output_file.open("wb") as output:
        try:
            proc = subprocess.Popen(
                [runtime, source, str(input_file)],
                cwd=ROOT,
                env=_child_env(folder),
                stdin=subprocess.PIPE if credentials is not None else subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_child_limits,
            )
        except OSError as error:
            raise DecodeFailure("ENGINE_UNAVAILABLE") from error
        try:
            if credentials is not None:
                proc.communicate(input=json.dumps(credentials).encode("utf-8"), timeout=timeout)
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
    return returncode, raw


def decode_file(suffix: str, contents: bytes, *, timeout: int = TIMEOUT_SECONDS, credentials: dict | None = None, full_hat: bool = False, compatible_export: dict | None = None) -> dict:
    """Execute one canonical file engine. The caller must authenticate first."""
    if compatible_export is not None:
        from exports.job import validate_options
        try: validate_options(compatible_export)
        except ValueError: raise DecodeFailure("INVALID_REQUEST") from None
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
    # The .hat and .bdnet cases supplied by the owner are complete Xhypher
    # text exports renamed without changing their content. Do not reinterpret
    # genuine HA Tunnel/BD NET files or guess unrelated encryption keys.
    input_suffix = suffix
    if _xhypher_export_in_renamed_file(suffix, contents):
        input_suffix = "xhypher"
        engine = load_runtime_file_engines()["xhypher"]
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
    if suffix == "hat" and (full_hat or compatible_export is not None) and input_suffix == "hat":
        # Cloud UI requires the complete document. Preserve the original
        # legacy route for frozen C2 reference output parity.
        # Historical hat.js flattens and drops nested configuration fields.
        # The full-result bridge decrypts the same envelope, preserves every
        # original JSON section and decodes known profilev5 values.
        engine = {**engine, "runtime": "python",
                  "source": "decoders/Python/apps/HA_Tunnel_Plus/hat_decoder.py"}
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
    # Content dispatch for suffixes shared by two different formats.
    # Predicates inspect bytes only; they never decrypt or guess keys.
    # - .hexcm starting with the HXS3 v3 container is Hex Custom 10.6.4
    #   (password arrives on stdin, see hex_custom_bridge.py); anything
    #   else keeps the existing Hex Tunnel 1.7.3 route.
    # - .tgv starting with STGCM2.VC./STGCM3.VC. is VC VPN 8.0 (bridge:
    #   that script takes --file, not a positional path); anything else
    #   keeps the TunelGuard 12.8 route.
    # - .ost that is not a Shield envelope keeps the frozen OUSS route;
    #   the C8 entry already points at Shield Tunnel.
    is_hex_custom = suffix == "hexcm" and _is_hex_custom_v3(contents)
    is_vc_tgv = suffix == "tgv" and _is_vc_tgv(contents)
    if is_hex_custom:
        engine = {
            "source": str(Path(__file__).with_name("hex_custom_bridge.py")),
            "runtime": "python",
            "name": "Hex Custom 10.6.4",
            "phase": "C8",
        }
    elif is_vc_tgv:
        engine = {
            "source": str(Path(__file__).with_name("vc_tgv_bridge.py")),
            "runtime": "python",
            "name": "VC VPN 8.0",
            "phase": "C8",
        }
    elif suffix == "ost" and not _is_shield_ost(contents):
        engine = load_file_engines()["ost"]
    if credentials is not None:
        allowed = {"password", "hwid"} if suffix == "hc" else {"password", "publicKey", "recipientKey"} if suffix == "npvs" else {"password"} if suffix in ("tut", "ua", "1ftnl", "v2box") or is_hex_custom else None
        if allowed is None or not isinstance(credentials, dict) or set(credentials) - allowed:
            raise DecodeFailure("CREDENTIALS_NOT_ALLOWED")
        for name, maximum in (("password", 4096), ("hwid", 128), ("publicKey", 128), ("recipientKey", 16384)):
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
    credential_input = protected_hc or protected_tut or protected_ua or protected_onef or protected_npvs or protected_v2box or is_hex_custom
    source = engine["source"]
    if suffix == "dark":
        source = str(Path(__file__).with_name("dark_bridge.py"))
    elif protected_hc:
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
    # Primary attempt plus, for C8 family overrides, one retry with the
    # frozen C0 family engine (see _C8_GENERIC_FALLBACK).
    attempts = [(engine, source, runtime, credential_input, credentials if credential_input else None)]
    if suffix in _C8_GENERIC_FALLBACK:
        canonical = load_file_engines().get(suffix)
        if canonical is not None and canonical["source"] != source:
            fallback_runtime = sys.executable if canonical["runtime"] == "python" else shutil.which(canonical["runtime"])
            if fallback_runtime:
                attempts.append((canonical, canonical["source"], fallback_runtime, False, None))

    with tempfile.TemporaryDirectory(prefix="spdecode-c2-") as folder:
        input_file = Path(folder) / ("input." + input_suffix)
        output_file = Path(folder) / "stdout"
        input_file.write_bytes(contents)
        input_file.chmod(0o600)
        raw = b""
        for index, (attempt_engine, attempt_source, attempt_runtime, attempt_cred_in, attempt_creds) in enumerate(attempts):
            engine = attempt_engine
            returncode, raw = _run_decoder_once(
                attempt_source, attempt_runtime, input_file, output_file,
                folder=folder,
                credentials=(attempt_creds if attempt_creds is not None else {}) if attempt_cred_in else None,
                timeout=timeout,
            )
            last = index == len(attempts) - 1
            if returncode != 0:
                if attempt_cred_in and returncode == 3:
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
                if last:
                    raise DecodeFailure("DECODE_FAILED")
                continue
            if not raw.strip():
                if last:
                    raise DecodeFailure("DECODE_FAILED")
                continue
            break
        else:
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
        hc_unresolved = suffix == "hc" and isinstance(structured, dict) and bool(structured.get("UnresolvedFields"))
        result = {
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
            "isPartial": hc_unresolved,
            "warnings": ["HC_UNRESOLVED_FIELDS"] if hc_unresolved else [],
        }
        if compatible_export is not None:
            from exports.job import prepare
            result["compatibleExport"] = prepare(suffix, contents, credentials, compatible_export, result)
        return result


def decode_provider_catalog(provider_id: str, contents: bytes) -> dict:
    """One fixed provider codec, child-isolated; broker performs all network I/O."""
    if provider_id not in ("thailand-vpn", "kham-vpn", "opentunnel-ssh", "md-proxy-vpn", "xxpicore-tunnel", "catnet-vpn", "litron-vpn", "litron-pro-vpn", "speigo-vpn-configs", "speigo-vpn-ssh", "genis-vpn", "speicers-turbo-vpn", "http-conexion", "namo-vpn", "fnf-tunnel-bd", "alsaher-vip", "halcon-r-net", "ha-tunnel-plus", "ultra-tunnel", "zig-tunnel", "enaa-tunnel", "alfaisal-tunnel-plus", "izph-vpn-pro", "vip-snipher-pro", "netcol-vpn", "wolf-custom-vpn", "jyfast-vpn-ultra", "tunneldoom-vpn", "mtm-tunnel-lite", "mnr-tunnel-plus", "bd-net-vpn", "aura-net-vpn", "apna-vpn", "any-vpn", "speicers-pro-vpn", "tx-tunnel", "mm-tunnel", "creeb-vpn", "abowaged-vpn", "7net-vpn", "xhypher-tunnel-pro", "ut-loop-pro-vpn", "turbomx-vpn", "superflash-vpn", "rmp-tunnel-pro", "rjc-tunnel-pro", "proneet-vpn", "onspace-vpn", "mx-tunnel-pro", "megatunnel", "http-internet-infinito", "24clan-green", "hx-tunnel", "mkk-hyper", "my-tunnel-proxy", "robust-tunnel", "royal-tunnel", "trv-tunnel", "4u-tunnel-lite", "ac-tunnel-vpn", "austroplus-vpn", "http-fenixvpn", "http-jireh", "http-socketclay", "http-wakko", "v2ray-tunnel-plus", "eut-vpn", "focus-vpn-cloud", "freedom-vpn", "tunelguard-vpn", "tunneltweak", "ksh-vpn", "dtunnel-mod"):
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
        child_env=_child_env(folder)
        if provider_id=="halcon-r-net":
            # Content key only; request signing material never reaches a decoder.
            key=os.environ.get("SPDECODE_HALCON_CATALOG_PASSWORD", "")
            if not key:
                raise DecodeFailure("REMOTE_NOT_CONFIGURED")
            child_env["SPDECODE_HALCON_CATALOG_PASSWORD"]=key
        source=Path(folder)/"catalog.enc"
        target=Path(folder)/"stdout"
        source.write_bytes(contents)
        source.chmod(0o600)
        try:
            with target.open("wb") as output:
                proc=subprocess.Popen(
                    [sys.executable,str(bridge),provider_id,str(source)],
                    cwd=ROOT,env=child_env,stdin=subprocess.DEVNULL,
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
            "warnings":["PARTIAL_SOURCE_FAILURE"] if provider_id=="mkk-hyper" and isinstance(structured,dict) and structured.get("complete") is False else (["El listado público de OpenTunnel contiene hosts SSH; el usuario y la contraseña se generan por cuenta en la aplicación oficial."] if provider_id=="opentunnel-ssh" else []),
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
