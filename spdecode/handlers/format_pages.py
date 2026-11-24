"""Build the public Telegram lists from the bot's registered formats."""
from __future__ import annotations

from spdecode.decoder_runtime import FILE_FORMATS, TEXT_FORMATS
from spdecode.format_names import family_text_application, file_application_name, public_format_name
from spdecode.utils import html_pre

_FEATURED_FILES = ("HTTP Custom", "HTTP Injector")


def _rows(entries, *, featured=(), multipart=()) -> list[str]:
    groups: dict[str, tuple[str, list[str]]] = {}
    unnamed = []
    for identifier, label in entries:
        if label:
            groups.setdefault(label.casefold(), (label, []))[1].append(identifier)
        else:
            unnamed.append(identifier)

    def app_order(label):
        return (featured.index(label) if label in featured else len(featured), label.casefold())

    def identifiers(items):
        return " ".join(f"<code>[{html_pre(item)}]</code>" for item in sorted(items, key=str.casefold))

    rows = []
    for label, items in sorted(groups.values(), key=lambda group: app_order(group[0])):
        note = " <i>· accepts fragments</i>" if label in multipart else ""
        rows.append(f"• <b>{html_pre(label)}</b> {identifiers(items)}{note}")
    rows.extend(f"• {identifiers(unnamed[start:start + 6])}" for start in range(0, len(unnamed), 6))
    return rows


def file_format_rows() -> list[str]:
    entries = (
        (f".{extension.upper()}", file_application_name(extension))
        for extension in sorted(FILE_FORMATS, key=str.casefold)
    )
    return _rows(entries, featured=_FEATURED_FILES)


def text_format_rows() -> list[str]:
    # Import the registered handlers lazily so their dispatch order stays the same.
    from spdecode.handlers.config_batch_texts import TEXT_HANDLERS
    from spdecode.handlers.extra_text_protocols import PROTOCOL_HANDLERS
    from spdecode.handlers.text_protocols import RENZ_TEXT_PROTOCOLS

    labels = {
        **{prefix: label for prefix, (label, _) in TEXT_HANDLERS.items()},
        **{prefix: label for prefix, (label, _) in PROTOCOL_HANDLERS.items()},
        **{prefix: family_text_application(prefix, variant) for prefix, variant in RENZ_TEXT_PROTOCOLS.items()},
        **TEXT_FORMATS,
        "dark://": "Dark Tunnel",
        "darktunnel://": "Dark Tunnel",
        "dt://": "Dark Tunnel",
        "dtunnel://": "Dark Tunnel",
        "mnrtunneludp://": "MNR Tunnel Plus",
        "ssc://": "SSC Custom",
        "tls://": "TLS Tunnel",
    }
    entries = {
        prefix.casefold(): (prefix, public_format_name(label))
        for prefix, label in labels.items()
    }
    return _rows(entries.values(), multipart=("Dark Tunnel", "SSC Custom"))
