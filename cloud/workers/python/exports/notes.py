"""SP-DECODE branded HC899 note, using the observed custom HTML renderer schema."""

from __future__ import annotations

import copy
from pathlib import Path

from .lossless import parse, put_member, equal

ASSETS = Path(__file__).resolve().parent / "notes"
LANGUAGES = ("es", "en")
LINKS = {
    "download": "https://spdecode.xyz",
    "channel": "https://t.me/GhostDeve",
    "community": "https://t.me/CodeBreakersHub",
    "developer": "https://t.me/Gh0stDeveloper",
}


def html_note(language="es"):
    if language not in LANGUAGES:
        raise ValueError("Unsupported note language")
    return (ASSETS / f"spdecode-note.{language}.html").read_text("utf-8").strip()


def plain_note(language="es"):
    if language not in LANGUAGES:
        raise ValueError("Unsupported note language")
    first = "Exportado con SP-DECODE" if language == "es" else "Exported with SP-DECODE"
    return (
        first + "\nDeveloper: Ghost Developer\nOrganization: Ghost Nexora Studio"
        "\nWebsite: "
        + LINKS["download"]
        + "\nTelegram: "
        + LINKS["channel"]
        + "\nCommunity: "
        + LINKS["community"]
    )


def validate_note_changes(before, after):
    """Allow only replacement/creation of the observed note slots and style.

    Unknown note metadata is preserved; this is never a protection override.
    """
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ValueError("Protection object must exist")
    if not isinstance(after.get("v"), str):
        raise ValueError("Note fallback must be text")
    style = after.get("x")
    if (
        not isinstance(style, dict)
        or type(style.get("v")) is not int
        or style["v"] != 1
    ):
        raise ValueError("Only observed note schema version 1 is supported")
    if style.get("s") != "custom" or not isinstance(style.get("h"), str):
        raise ValueError("Custom HTML note requires string h and custom style")
    previous = before.get("x")
    if previous is not None:
        if not isinstance(previous, dict) or (
            type(previous.get("v", 1)) is not int or previous.get("v", 1) != 1
        ):
            raise ValueError("Unsupported original note style version")
        if not equal(
            {k: v for k, v in previous.items() if k not in ("v", "s", "h")},
            {k: v for k, v in style.items() if k not in ("v", "s", "h")},
        ):
            raise ValueError("Unknown note style metadata changed")
    elif set(style) != {"v", "s", "h"}:
        raise ValueError("Unobserved note fields added")
    if "e" in before:
        if type(before["e"]) is not bool or after.get("e") is not True:
            raise ValueError(
                "Existing note-enabled flag must remain boolean and enabled"
            )
    elif "e" in after:
        raise ValueError("Do not invent a note-enabled flag absent from the source")
    old_other = {k: v for k, v in before.items() if k not in ("v", "x", "e")}
    new_other = {k: v for k, v in after.items() if k not in ("v", "x", "e")}
    if not equal(old_other, new_other):
        raise ValueError("Fields outside the note changed")


def replace_note(raw_main: bytes, language="es") -> bytes:
    original = parse(raw_main)
    if not isinstance(original, dict) or not isinstance(original.get("g"), dict):
        raise ValueError("Expected existing main.g object")
    old_g = original["g"]
    if old_g.get("x") is not None and (
        not isinstance(old_g["x"], dict)
        or (type(old_g["x"].get("v", 1)) is not int or old_g["x"].get("v", 1) != 1)
    ):
        raise ValueError("Unsupported original note style version")
    result = put_member(raw_main, ("g",), "v", plain_note(language))
    if old_g.get("x") is None:
        result = put_member(
            result, ("g",), "x", {"v": 1, "s": "custom", "h": html_note(language)}
        )
    else:
        for name, value in [("v", 1), ("s", "custom"), ("h", html_note(language))]:
            result = put_member(result, ("g", "x"), name, value)
    if "e" in old_g:
        result = put_member(result, ("g",), "e", True)
    updated = parse(result)
    validate_note_changes(old_g, updated["g"])
    if not equal(
        {k: v for k, v in original.items() if k != "g"},
        {k: v for k, v in updated.items() if k != "g"},
    ):
        raise AssertionError("Unrelated main fields changed")
    return result
