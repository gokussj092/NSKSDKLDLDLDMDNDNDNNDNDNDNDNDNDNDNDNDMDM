"""Ultra Tunnel build 59 catalogs; exact Argon2id/GCM and getter contexts.

Format constants reuse the existing Ultra/Sandok profile verified against the
current native updater. No alternate app profiles or unauthenticated fallback.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import sys

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES

if __package__ and "." in __package__:
    from ... import ultra
    from ..HTTP_FenixVPN import codec as shared
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import ultra
    from apps.HTTP_FenixVPN import codec as shared

DecodeError = shared.DecodeError
MAX_BYTES = shared.MAX_BYTES
MAX_FIELDS = 8192
render = shared.render
PROFILE = ultra.VPNS_SD["ultratunnel"]
TOP_FIELDS = ("DefOVPNUser", "DefOVPNPass", "HysteriaUser", "HysteriaOBFS", "DefaultOVPNCert")
SERVER_FIELDS = ("ServerIPHost", "OVPNUser", "OVPNPass", "UDP_obfs", "UDP_user", "CustomCertificate",
                 "SlowDNSHost", "SlowDNSKey", "V2rayUUID", "V2rayPath", "H2pass", "TrojanPass")
NETWORK_FIELDS = ("Payload", "CustomProxy", "SNI", "V2rayConfig", "BugDNS", "V2rayAddress", "V2rayHost", "V2raySNI")


def open_envelope(text: str, *, remote: bool = False) -> str:
    try:
        if not isinstance(text, str) or not text or len(text.encode("utf-8")) > MAX_BYTES:
            raise ValueError()
        if remote:
            if len(text) < 4 or text[3] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
                raise ValueError()
            text = text[:3] + text[4:]
        raw = base64.b64decode(text.replace("\r", "").replace("\n", ""), validate=True)
        if len(raw) < 44:
            raise ValueError()
        key = hash_secret_raw(PROFILE["password"] if remote else PROFILE["password2"], raw[:16],
                              3, PROFILE["mem"], 1, 32, Type.ID, version=19)
        cipher = AES.new(key, AES.MODE_GCM, nonce=raw[16:28])
        cipher.update(raw[:16])
        return cipher.decrypt_and_verify(raw[28:-16], raw[-16:]).decode("utf-8")
    except (ValueError, UnicodeError, TypeError) as error:
        raise DecodeError("Sobre Ultra Tunnel inválido o incompatible.") from error


def decode_catalog(data: bytes, *, field_workers: int = 1) -> dict:
    try:
        if field_workers not in (1, 2):
            raise ValueError()
        text = shared._bounded(data).decode("utf-8-sig").strip()
        if not text.startswith("{"):
            # Native decrypt removes byte index 3; bundled EO/DO has no marker.
            # Select the framing before GCM, never retry a failed tag with another key.
            remote = len(text.replace("\r", "").replace("\n", "")) % 4 == 1
            text = open_envelope(text, remote=remote)
        obj = json.loads(text, object_pairs_hook=shared._unique, parse_constant=shared._constant)
        shared._validate(obj)
        if (not isinstance(obj, dict) or not isinstance(obj.get("Version"), str) or not obj["Version"]
                or any(not isinstance(obj.get(name), list) or not obj[name] for name in ("Servers", "Networks"))):
            raise ValueError()
        cache = {}

        if field_workers == 2:
            # MD PROXY uses thousands of independent Argon2id field keys. The
            # verified derivations release the GIL; two bounded threads fit a
            # small dual-vCPU worker without changing crypto parameters.
            unique = set()
            pending = []

            def collect(record, names):
                for name in names:
                    value = record.get(name)
                    if not isinstance(value, str):
                        continue
                    packed = value.replace("\r", "").replace("\n", "")
                    if len(packed) >= 60 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", packed):
                        if packed not in unique:
                            if len(unique) >= MAX_FIELDS:
                                raise ValueError()
                            unique.add(packed)
                            pending.append((packed, value))

            collect(obj, TOP_FIELDS)
            for section, names in (("Servers", SERVER_FIELDS), ("Networks", NETWORK_FIELDS)):
                for row in obj[section]:
                    if not isinstance(row, dict) or not isinstance(row.get("Name"), str):
                        raise ValueError()
                    collect(row, names)

            # Only two Argon2id jobs may exist at once: no unbounded future
            # queue, plaintext cache on disk, fallback keys or partial output.
            with ThreadPoolExecutor(max_workers=2) as pool:
                for offset in range(0, len(pending), 2):
                    batch = pending[offset:offset + 2]
                    values = list(pool.map(lambda item: open_envelope(item[1]), batch))
                    for (packed, _), plaintext in zip(batch, values):
                        cache[packed] = plaintext

        def fields(record, names):
            result = record.copy()
            for name in names:
                value = record.get(name)
                if not isinstance(value, str):
                    continue  # Preserve optional nulls/scalars and unknown metadata.
                packed = value.replace("\r", "").replace("\n", "")
                if len(packed) >= 60 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", packed):
                    if packed not in cache:
                        if len(cache) >= MAX_FIELDS:
                            raise ValueError()
                        cache[packed] = open_envelope(value)
                    result[name] = cache[packed]
            return result

        result = fields(obj, TOP_FIELDS)
        for section, names in (("Servers", SERVER_FIELDS), ("Networks", NETWORK_FIELDS)):
            result[section] = []
            for row in obj[section]:
                if not isinstance(row, dict) or not isinstance(row.get("Name"), str):
                    raise ValueError()
                result[section].append(fields(row, names))
        shared._validate(result)
        render(result)
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise DecodeError("No se pudo leer el catálogo Ultra Tunnel completo.") from error
