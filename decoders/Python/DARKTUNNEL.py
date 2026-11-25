#!/usr/bin/env python3
"""DarkTunnel 1.0.26 decoder for SP-DECODE.

Decodes ``darktunnel://`` links (SSH and VLESS split-blob variants) and
``.dark`` files (same locked envelope).

Layers (all VERIFIED_REAL against the 1.0.26 APK and the real "30dayz" link):
  1. Outer envelope: base64url -> JSON header + encrypted blob. The VLESS
     variant splits the blob between a base64 value and raw trailing bytes
     (``_split_blob_outer``); the SSH variant carries it whole in the
     ``encryptedLockedConfig`` JSON value.
  2. Outer blob: AES-128-CFB, KEY_256, static IV -> MessagePack map with
     ``LockedAppConfig`` + ``EncryptedLockedConfig``. The outer MessagePack
     object is followed by 272 opaque trailing bytes which the app ignores.
  3. Inner blob: AES-192-CFB, KEY_192, static IV -> MessagePack map with
     ``InjectConfig`` / ``SshConfig`` / ``V2RayConfig``.
  4. Each ``Encrypted*`` field: AES-192-CFB, KEY_192, static IV
     (the app's ``util.Dtos`` / ``Efroms`` pair in libgojni.so).

KNOWN LIMIT — V2RayConfig.EncryptedConfig (844 B) is only PARTIALLY open:
applying the app's own decryptor (``libv2ray.(*V2RayConfig).GetConfig`` ->
``util.Dtos``) yields a 30-byte JSON skeleton fragment
``{"inbounds":[{"listen":"$SOCKS:2`` and 812 bytes that do not parse as
JSON under any tested scheme (see ANALISIS.md, section "EncryptedConfig").
The decoder therefore returns the fragment plus the raw tail (as a byte
list) and marks the section ``status: "partial"`` instead of inventing a
decryption. The VLESS server address/UUID/port live inside that tail, so a
"30dayz" decode is complete everywhere EXCEPT the V2Ray server details.

Static keys below are app constants extracted from the APK (same values as
the SP-DECODE repo decoder ``decoders/Python/DARKTUNNEL.py``); they are NOT
user credentials. No profile credential (server address, UUID, username,
password, per-profile key) is stored in this file.

Requires: pycryptodome, msgpack.
CLI:  python darktunnel.py <link-or-file>
      python darktunnel.py --self-test   (structural summary, no credentials)
"""
import base64
import contextlib
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from Crypto.Cipher import AES

try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    MSGPACK_AVAILABLE = False


APP_PACKAGE = "net.darktunnel.app"
APP_VERSION_NAME = "1.0.26"
APP_VERSION_CODE = 32


class DTConstants:
    """Static crypto constants of the DarkTunnel app (from libgojni.so)."""
    KEY_256: bytes = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
    KEY_192: bytes = b"F)J@NcRfUjXn2r4u7x!A%D*G"
    IV: bytes = bytes.fromhex("232e39185523184a5723586242200e05")


def _format_top_level_json(data):
    """Format only the root JSON keys (as in the SP-DECODE repo decoder)."""
    if not isinstance(data, dict):
        if isinstance(data, (list, tuple)):
            value = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
        elif data is None:
            value = "null"
        elif isinstance(data, bool):
            value = "true" if data else "false"
        else:
            value = str(data)
        return f"│[۞] DATA: {value}"

    lines = []
    for key, value in data.items():
        if isinstance(value, (dict, list, tuple)):
            rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
        elif value is None:
            rendered = "null"
        elif isinstance(value, bool):
            rendered = "true" if value else "false"
        else:
            rendered = str(value)
        lines.append(f"│[۞] {key}: {rendered}")
    return "\n".join(lines)


class DTDecryptor:
    """Core decryption and parsing engine for DarkTunnel configs."""

    _ELC_MARKER: bytes = b'"encryptedLockedConfig":"'
    _B64_CHARS = frozenset(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
    )

    @staticmethod
    def _base64_decode_safe(data: str) -> bytes:
        clean_data = data.replace("-", "+").replace("_", "/")
        if pad := len(clean_data) % 4:
            clean_data += "=" * (4 - pad)
        return base64.b64decode(clean_data)

    @staticmethod
    def _unpack_first(data: bytes) -> Any:
        """Unpack the first MessagePack object, ignoring trailing bytes.

        Some envelopes carry opaque bytes after the first object (the VLESS
        split-blob variant appends 272 trailing bytes after the outer map);
        unpackb would raise "extra data" on them. The app reads the first
        object and ignores the rest, so we do the same.
        """
        unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
        unpacker.feed(data)
        return next(unpacker)

    @classmethod
    def _split_blob_outer(cls, decoded: bytes) -> tuple:
        """Parse a split-blob outer envelope (VLESS variant).

        The outer payload is NOT valid JSON: it is a JSON header
        ({"type":"VLESS","name":...,"vlessTunnelConfig":{...},
        "encryptedLockedConfig":"<base64 part>") followed by the rest of the
        encrypted blob as raw bytes. Returns (header_dict, blob_bytes) or
        (None, None) when the shape does not match.
        """
        pos = decoded.find(cls._ELC_MARKER)
        if pos < 0:
            return None, None
        try:
            header = json.loads(decoded[: pos + len(cls._ELC_MARKER)] + b'"}')
        except Exception:
            return None, None
        b64_start = pos + len(cls._ELC_MARKER)
        end = b64_start
        while end < len(decoded) and decoded[end] in cls._B64_CHARS:
            end += 1
        if end == b64_start or end >= len(decoded):
            return None, None
        try:
            blob = cls._base64_decode_safe(
                decoded[b64_start:end].decode("ascii")
            ) + decoded[end:]
        except Exception:
            return None, None
        if not blob:
            return None, None
        return header, blob

    @staticmethod
    def _aes_cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)

    @staticmethod
    def _is_utf8_printable(value: bytes) -> bool:
        if not value:
            return False
        try:
            return bool(re.fullmatch(r"[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F]*", value.decode("utf-8")))
        except UnicodeDecodeError:
            return False

    @classmethod
    def _try_parse_json_string(cls, value: str) -> Union[Dict, List, str]:
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            with contextlib.suppress(Exception):
                fixed_json = re.sub(r'(:\s*)(\$[A-Za-z0-9_]+)', r'\1"\2"', stripped)
                return cls._normalize_for_json(json.loads(fixed_json))
        return value

    @classmethod
    def _normalize_for_json(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: cls._normalize_for_json(v) for k, v in value.items() if k != "Password"}

        if isinstance(value, list):
            return [cls._normalize_for_json(v) for v in value]

        if isinstance(value, bytes):
            return value.decode("utf-8") if cls._is_utf8_printable(value) else list(value)

        if isinstance(value, str):
            return value

        return value

    @classmethod
    def _decrypt_v2ray_config(cls, raw: bytes) -> Dict[str, Any]:
        """Decrypt V2RayConfig.EncryptedConfig exactly as the app does.

        The app (libgojni.so, ``libv2ray.(*V2RayConfig).GetConfig``) calls
        ``util.Dtos``: AES-CFB/KEY_192 with the static IV, then replaces the
        placeholders $SOCKS5_LISTEN_HOST, $SOCKS5_LISTEN_PORT,
        $HTTP_LISTEN_HOST, $HTTP_LISTEN_PORT, $MUX_ENABLED. The replacement
        only makes sense on a complete JSON template; on the real "30dayz"
        link the decryption yields a 30-byte JSON skeleton fragment and
        812 bytes that do not parse as JSON under any tested scheme, so the
        section is returned as PARTIAL with the raw tail preserved.
        """
        dec = cls._aes_cfb_decrypt(bytes(raw), DTConstants.KEY_192, DTConstants.IV)
        # The JSON skeleton fragment: leading bytes that form the start of a
        # JSON object (``{"inbounds":...``). Everything after the fragment
        # is the unopened tail.
        prefix_len = 0
        for i, b in enumerate(dec):
            if 32 <= b < 127:
                prefix_len = i + 1
            else:
                break
        # The fragment is only meaningful if it is a JSON start; otherwise
        # the whole blob is tail.
        prefix = dec[:prefix_len] if dec[:1] == b"{" else b""
        tail = dec[len(prefix):]
        json_ok = False
        with contextlib.suppress(Exception):
            json.loads(prefix.decode("utf-8"))
            json_ok = True
        status = "open" if (json_ok and not tail) else "partial"
        return {
            "status": status,
            "method": "AES-CFB KEY_192 static-IV (app util.Dtos)",
            "length": len(raw),
            "sha256": hashlib.sha256(bytes(raw)).hexdigest(),
            "json_prefix": prefix.decode("utf-8", errors="replace"),
            "json_prefix_bytes": len(prefix),
            "json_parseable": json_ok,
            "tail_bytes": len(tail),
            "tail_sha256": hashlib.sha256(tail).hexdigest(),
            "tail_raw": list(tail),
        }

    @classmethod
    def _clean_encrypted(cls, value: Any, key: bytes, iv: bytes) -> Any:
        if isinstance(value, dict):
            cleaned = {}
            for k, v in value.items():
                if isinstance(k, str) and k.startswith("Encrypted") and v and isinstance(v, (bytes, bytearray)):
                    if k == "EncryptedConfig":
                        cleaned[k] = cls._decrypt_v2ray_config(bytes(v))
                    else:
                        try:
                            cleaned[k] = cls._aes_cfb_decrypt(bytes(v), key, iv)
                        except Exception:
                            cleaned[k] = v
                else:
                    cleaned[k] = cls._clean_encrypted(v, key, iv)
            return cleaned

        if isinstance(value, list):
            return [cls._clean_encrypted(v, key, iv) for v in value]

        return value

    @classmethod
    def decode_structured(cls, file_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Decode a link/file into a structured dict (layers + statuses)."""
        if not MSGPACK_AVAILABLE:
            return None
        with contextlib.suppress(Exception):
            raw_input = file_bytes.decode("utf-8", errors="ignore").strip()
            if not raw_input:
                return None
            # SHA-256 of the whole input file (scheme included), so the value
            # matches an external `sha256sum` of the link file.
            link_sha256 = hashlib.sha256(file_bytes).hexdigest()
            if "://" in raw_input:
                raw_input = raw_input.split("://", 1)[1]

            outer = None
            encrypted_blob = None
            decoded_outer = cls._base64_decode_safe(raw_input)
            with contextlib.suppress(Exception):
                outer = json.loads(decoded_outer.decode("utf-8"))
                encrypted_blob = cls._base64_decode_safe(outer["encryptedLockedConfig"])
            variant = "ssh-json"
            if outer is None or encrypted_blob is None:
                outer, encrypted_blob = cls._split_blob_outer(decoded_outer)
                variant = "vless-split-blob"
            if outer is None or not encrypted_blob:
                return None

            decrypted_outer = cls._aes_cfb_decrypt(encrypted_blob, DTConstants.KEY_256, DTConstants.IV)
            unpacked_outer = cls._unpack_first(decrypted_outer)
            result: Dict[str, Any] = {
                "app": {"package": APP_PACKAGE, "version_name": APP_VERSION_NAME,
                        "version_code": APP_VERSION_CODE},
                "variant": variant,
                "link_sha256": link_sha256,
                "outer": {
                    "type": outer.get("type"),
                    "name": outer.get("name"),
                    "blob_bytes": len(encrypted_blob),
                    "blob_sha256": hashlib.sha256(encrypted_blob).hexdigest(),
                    "decrypted_bytes": len(decrypted_outer),
                    "outer_object_bytes": None,
                    "outer_trailing_bytes": None,
                },
                "locked_app_config": {},
                "inner": {},
            }
            # Measure the outer trailing bytes properly: re-pack is not a
            # length measure; instead re-unpack with a byte counter.
            unpacker = msgpack.Unpacker(raw=False, strict_map_key=False)
            consumed = None
            for n in range(1, len(decrypted_outer) + 1):
                unpacker.feed(decrypted_outer[n - 1:n])
                try:
                    next(unpacker)
                    consumed = n
                    break
                except StopIteration:
                    pass
            result["outer"]["outer_object_bytes"] = consumed
            result["outer"]["outer_trailing_bytes"] = (
                len(decrypted_outer) - consumed if consumed is not None else None
            )
            if consumed is not None and consumed < len(decrypted_outer):
                result["outer"]["outer_trailing_sha256"] = hashlib.sha256(
                    decrypted_outer[consumed:]
                ).hexdigest()

            lac = unpacked_outer.get("LockedAppConfig", {})

            def _as_str(v):
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).decode("utf-8", errors="replace")
                return v

            result["locked_app_config"] = {
                "VersionCode": lac.get("VersionCode"),
                "VersionName": _as_str(lac.get("VersionName")),
                "TunnelType": _as_str(lac.get("TunnelType")),
                "IsSshLocked": lac.get("IsSshLocked"),
                "ExpiredAtTimestamp": lac.get("ExpiredAtTimestamp"),
                "HardwareIdList": lac.get("HardwareIdList"),
                "Message_bytes": len(lac.get("Message", b"") or b""),
                "ConnectedMessage_bytes": len(lac.get("ConnectedMessage", b"") or b""),
                "Password_bytes": len(lac.get("Password", b"") or b""),
            }

            if "EncryptedLockedConfig" in unpacked_outer:
                inner_enc = bytes(unpacked_outer["EncryptedLockedConfig"])
                decrypted_inner = cls._aes_cfb_decrypt(inner_enc, DTConstants.KEY_192, DTConstants.IV)
                unpacked_inner = cls._unpack_first(decrypted_inner)
                cleaned = cls._clean_encrypted(unpacked_inner, DTConstants.KEY_192, DTConstants.IV)
                result["inner"] = {
                    "encrypted_bytes": len(inner_enc),
                    "decrypted_bytes": len(decrypted_inner),
                    "sections": cleaned,
                }
            return result
        return None

    @classmethod
    def execute(cls, file_bytes: bytes) -> Optional[str]:
        if not MSGPACK_AVAILABLE:
            return None

        with contextlib.suppress(Exception):
            raw_input = file_bytes.decode("utf-8", errors="ignore").strip()
            if not raw_input:
                return None

            if "://" in raw_input:
                raw_input = raw_input.split("://", 1)[1]

            outer = None
            encrypted_blob = None
            decoded_outer = cls._base64_decode_safe(raw_input)
            with contextlib.suppress(Exception):
                outer = json.loads(decoded_outer.decode("utf-8"))
                encrypted_blob = cls._base64_decode_safe(outer["encryptedLockedConfig"])
            if outer is None or encrypted_blob is None:
                # VLESS variant: the outer payload is a JSON header plus the
                # encrypted blob split between a base64 value and raw bytes.
                outer, encrypted_blob = cls._split_blob_outer(decoded_outer)
            if outer is None or not encrypted_blob:
                return None

            decrypted_outer = cls._aes_cfb_decrypt(encrypted_blob, DTConstants.KEY_256, DTConstants.IV)
            unpacked_outer = cls._unpack_first(decrypted_outer)

            if "EncryptedLockedConfig" in unpacked_outer:
                decrypted_inner = cls._aes_cfb_decrypt(unpacked_outer["EncryptedLockedConfig"], DTConstants.KEY_192, DTConstants.IV)
                unpacked_inner = cls._unpack_first(decrypted_inner)
                unpacked_outer["EncryptedLockedConfig"] = cls._clean_encrypted(unpacked_inner, DTConstants.KEY_192, DTConstants.IV)

            outer["encryptedLockedConfig"] = unpacked_outer
            normalized = cls._normalize_for_json(outer)

            return (
                f"┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.dark)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n"
                f"{_format_top_level_json(normalized)}\n\n"
                f"├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n"
            )

        return None


def run(file_bytes: bytes) -> Optional[str]:
    """Entry point for seamless integration."""
    return DTDecryptor.execute(file_bytes)


def _self_test() -> int:
    """Structural self-test against the real 30dayz link (if present) or the
    synthetic fixture. Prints structure only — NO credentials."""
    here = Path(__file__).resolve().parent
    real = Path.home() / "workspace" / "user" / "files" / "Dark_tunel_0_pv29.txt"
    fixture = here / "fixtures" / "synthetic_link.txt"
    if real.is_file():
        target, label = real, "real 30dayz link"
    elif fixture.is_file():
        target, label = fixture, "synthetic fixture"
    else:
        print("self-test: no link file found (real link or fixtures/synthetic_link.txt)", file=sys.stderr)
        return 1

    data = target.read_bytes()
    res = DTDecryptor.decode_structured(data)
    if res is None:
        print(f"self-test [{label}]: FAILED to decode", file=sys.stderr)
        return 1

    print(f"self-test [{label}] file={target.name}")
    print(f"  app: {res['app']['package']} {res['app']['version_name']} (code {res['app']['version_code']})")
    print(f"  variant: {res['variant']}  type={res['outer']['type']} name={res['outer']['name']}")
    print(f"  outer blob: {res['outer']['blob_bytes']} B sha256={res['outer']['blob_sha256'][:16]}…")
    print(f"  outer msgpack object: {res['outer']['outer_object_bytes']} B, trailing: {res['outer']['outer_trailing_bytes']} B"
          + (f" sha256={res['outer'].get('outer_trailing_sha256','')[:16]}…" if res['outer'].get('outer_trailing_sha256') else ""))
    lac = res["locked_app_config"]
    print(f"  LockedAppConfig: v{lac['VersionName']} code={lac['VersionCode']} tunnel={lac['TunnelType']} "
          f"ssh_locked={lac['IsSshLocked']} expires_ms={lac['ExpiredAtTimestamp']} hw_ids={lac['HardwareIdList']}")
    inner = res["inner"]
    print(f"  inner blob: {inner['encrypted_bytes']} B -> {inner['decrypted_bytes']} B msgpack")
    secs = inner["sections"]
    for name, sec in secs.items():
        if isinstance(sec, dict):
            fields = []
            for k, v in sec.items():
                if isinstance(v, dict) and v.get("status") == "partial":
                    fields.append(f"{k}=PARTIAL({v['json_prefix_bytes']}B prefix, {v['tail_bytes']}B tail unopened)")
                elif isinstance(v, dict) and v.get("status") == "open":
                    fields.append(f"{k}=OPEN({v['json_prefix_bytes']}B JSON)")
                elif isinstance(v, (bytes, bytearray)):
                    # Redacted: report only whether it decrypted to text.
                    txt = DTDecryptor._is_utf8_printable(bytes(v))
                    fields.append(f"{k}={'decrypted-text' if txt else 'raw'}({len(v)}B)")
                elif isinstance(v, list):
                    fields.append(f"{k}=list[{len(v)}]")
                else:
                    fields.append(f"{k}={v!r}")
            print(f"  {name}: " + "; ".join(fields))
    vc = secs.get("V2RayConfig", {}).get("EncryptedConfig", {})
    if isinstance(vc, dict) and vc.get("status") == "partial":
        print(f"  V2Ray EncryptedConfig: {vc['length']} B sha256={vc['sha256'][:16]}…")
        print(f"    json_prefix: {vc['json_prefix']!r} (parseable={vc['json_parseable']})")
        print(f"    tail: {vc['tail_bytes']} B unopened sha256={vc['tail_sha256'][:16]}…")
        print("  VERDICT: outer+inner layers OPEN; V2Ray server details (address/UUID/port) "
              "remain inside the unopened tail — see ANALISIS.md")
    else:
        print("  VERDICT: all layers open")
    return 0


def main() -> int:
    """CLI: python SCRIPT.py "archivo.ext" | python SCRIPT.py --self-test."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return _self_test()

    if len(sys.argv) != 2:
        print(f'Uso: {Path(sys.argv[0]).name} "archivo" | --self-test', file=sys.stderr)
        return 2

    input_path = Path(sys.argv[1])
    if not input_path.is_file():
        print(f"No se encontró el archivo: {input_path}", file=sys.stderr)
        return 2

    try:
        file_bytes = input_path.read_bytes()
    except OSError as exc:
        print(f"No se pudo leer el archivo: {exc}", file=sys.stderr)
        return 2

    try:
        result = run(file_bytes)
    except Exception as exc:
        print(f"Error al ejecutar el decodificador: {exc}", file=sys.stderr)
        return 1

    if not result:
        print("No se pudo decodificar el archivo o su formato no es válido.", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
