"""Bounded, offline extraction of the declared APK package and literal label.

The manifest is compiled Android XML (AXML). This parser does not resolve
third-party resources and never executes APK content. Missing labels are null.
"""
from __future__ import annotations
from pathlib import Path
import re
import struct
import tempfile
import zipfile

PKG = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){1,15}\Z")
MAX_XML = 8 * 1024 * 1024
MAX_BASE = 100 * 1000 * 1000


def _u16(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(buf):
        raise ValueError("AXML_BOUNDS")
    return struct.unpack_from("<H", buf, offset)[0]


def _u32(buf: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(buf):
        raise ValueError("AXML_BOUNDS")
    return struct.unpack_from("<I", buf, offset)[0]


def _length(buf: bytes, offset: int, utf8: bool) -> tuple[int, int]:
    if utf8:
        if offset >= len(buf):
            raise ValueError("AXML_BOUNDS")
        value = buf[offset]
        offset += 1
        if value & 0x80:
            if offset >= len(buf):
                raise ValueError("AXML_BOUNDS")
            value = ((value & 0x7f) << 8) | buf[offset]
            offset += 1
        return value, offset
    first = _u16(buf, offset)
    offset += 2
    if first & 0x8000:
        first = ((first & 0x7fff) << 16) | _u16(buf, offset)
        offset += 2
    return first, offset


def _strings(buf: bytes, off: int, size: int) -> list[str]:
    header = _u16(buf, off + 2)
    count = _u32(buf, off + 8)
    flags = _u32(buf, off + 16)
    base = off + _u32(buf, off + 20)
    if header < 28 or count > 150_000 or off + header + count * 4 > off + size:
        raise ValueError("AXML_STRINGS")
    utf8 = bool(flags & 0x100)
    result = []
    for idx in range(count):
        pos = base + _u32(buf, off + header + idx * 4)
        if pos < off or pos >= off + size:
            raise ValueError("AXML_STRING_OFFSET")
        _, pos = _length(buf, pos, utf8)
        if utf8:
            size_bytes, pos = _length(buf, pos, True)
        else:
            size_chars = _
            size_bytes = size_chars * 2
        if size_bytes > 65536 or pos + size_bytes > off + size:
            raise ValueError("AXML_STRING_LENGTH")
        result.append(buf[pos:pos + size_bytes].decode("utf-8" if utf8 else "utf-16le", "replace"))
    return result


def _parse(axml: bytes) -> dict:
    if len(axml) < 8 or _u16(axml, 0) != 3 or _u16(axml, 2) != 8:
        raise ValueError("AXML_INVALID")
    limit = min(len(axml), _u32(axml, 4))
    if limit < 8:
        raise ValueError("AXML_INVALID")
    pool = []
    package = None
    label = None
    off = 8
    while off + 8 <= limit:
        kind = _u16(axml, off)
        head = _u16(axml, off + 2)
        length = _u32(axml, off + 4)
        if head < 8 or length < head or off + length > limit:
            raise ValueError("AXML_CHUNK")
        if kind == 1:
            pool = _strings(axml, off, length)
        if kind == 0x0102 and pool and head >= 16 and length >= 36:
            ext = off + 16
            tag_idx = _u32(axml, ext + 4)
            tag = pool[tag_idx] if tag_idx < len(pool) else ""
            if tag in ("manifest", "application"):
                attr_start = _u16(axml, ext + 8)
                attr_size = _u16(axml, ext + 10)
                attr_count = _u16(axml, ext + 12)
                if attr_size < 20 or attr_count > 128 or ext + attr_start + attr_count * attr_size > off + length:
                    raise ValueError("AXML_ATTRIBUTES")
                for n in range(attr_count):
                    a = ext + attr_start + n * attr_size
                    name_idx = _u32(axml, a + 4)
                    name = pool[name_idx] if name_idx < len(pool) else ""
                    raw_idx = _u32(axml, a + 8)
                    data_type = axml[a + 15]
                    data_idx = _u32(axml, a + 16)
                    value_idx = raw_idx if raw_idx != 0xffffffff else data_idx if data_type == 3 else 0xffffffff
                    value = pool[value_idx] if value_idx < len(pool) else None
                    if tag == "manifest" and name == "package" and value and PKG.fullmatch(value):
                        package = value
                    if tag == "application" and name == "label" and value and 0 < len(value) <= 100:
                        label = value
        off += length
    return {"packageName": package, "appName": label,
            "identitySource": "COMPILED_ANDROID_MANIFEST" if package else "UNRESOLVED"}


def inspect_identity(source: Path, kind: str) -> dict:
    fallback = {"packageName": None, "appName": None, "identitySource": "UNRESOLVED"}
    try:
        with zipfile.ZipFile(source) as outer:
            if kind == "APK":
                with outer.open("AndroidManifest.xml") as member:
                    xml = member.read(MAX_XML + 1)
            else:
                members = [x for x in outer.infolist() if x.filename == "base.apk"]
                if len(members) != 1 or members[0].file_size > MAX_BASE:
                    return fallback
                with tempfile.TemporaryFile(mode="w+b", dir=source.parent) as spool:
                    with outer.open(members[0]) as member:
                        copied = 0
                        while chunk := member.read(262144):
                            copied += len(chunk)
                            if copied > MAX_BASE or copied > members[0].file_size:
                                return fallback
                            spool.write(chunk)
                    if copied != members[0].file_size:
                        return fallback
                    spool.seek(0)
                    with zipfile.ZipFile(spool) as apk:
                        with apk.open("AndroidManifest.xml") as member:
                            xml = member.read(MAX_XML + 1)
        if not 8 <= len(xml) <= MAX_XML:
            return fallback
        return _parse(xml)
    except (OSError, KeyError, ValueError, RuntimeError, struct.error, zipfile.BadZipFile):
        return fallback
