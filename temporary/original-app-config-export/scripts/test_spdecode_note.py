#!/usr/bin/env python3
"""Regressions for replacing all note sources and preserving unrelated data."""

import copy
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path

from hc_hcx4_n11_experiment import hc, codec, seal
from spdecode_note import replace_note, html_note, plain_note, LINKS
from lossless_json import parse, put_member
from write_hc_html_note import with_html_note
from test_hc_open_layout import image
from hc_open_layout_experiment import convert


class LinksParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.tags = []
        self.bad = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        for key, value in attrs:
            if key.startswith("on"):
                self.bad.append(key)
            if key in ("src", "srcset"):
                self.bad.append(key)
            if key == "href":
                self.links.append(value)


class NoteTests(unittest.TestCase):
    def test_default_converter_adds_html_when_source_note_is_absent(self):
        raw = image()
        env = codec.open_envelope(raw)
        key, aad = codec.derive(env, None, None)
        main = codec.decrypt(raw)["main"]
        main["g"].pop("v")
        env["i"]["b"], env["i"]["c"] = seal(
            key, aad + b"\0m", json.dumps(main).encode()
        )
        nonce, cipher = seal(codec.OUTER_KEY, codec.OUTER_AAD, json.dumps(env).encode())
        source = bytes.fromhex(nonce + cipher)
        for combined in (False, True):
            result, _ = convert(source, image(opened=True), combined=combined)
            self.assertEqual(codec.decrypt(result)["main"]["g"]["x"]["h"], html_note())

    def main_image(self, value):
        return json.dumps(
            {
                "g": value,
                "u": "https://example.invalid/",
                "unknown": {"keep": [0, False, None]},
            }
        ).encode()

    def test_overwrites_all_prior_note_styles(self):
        for style in ("default", "note", "custom"):
            source = {
                "a": "none",
                "c": True,
                "d": 1900000000,
                "v": "OLD_PRIVATE_NOTE",
                "x": {
                    "v": 1,
                    "s": style,
                    "h": "OLD_PRIVATE_HTML",
                    "unknown": {"keep": [0, False]},
                },
                "e": False,
            }
            result = parse(replace_note(self.main_image(source)))
            self.assertEqual(result["g"]["v"], plain_note())
            self.assertEqual(result["g"]["x"]["h"], html_note())
            self.assertEqual(result["g"]["x"]["s"], "custom")
            self.assertEqual(result["g"]["x"]["unknown"], source["x"]["unknown"])
            self.assertTrue(result["g"]["e"])
            self.assertTrue(result["g"]["c"])
            self.assertEqual(result["g"]["d"], 1900000000)
            self.assertNotIn("OLD_PRIVATE", json.dumps(result))

    def test_empty_absent_null_notes_get_same_template(self):
        for source in (
            {"a": "none"},
            {"a": "none", "v": ""},
            {"a": "none", "v": None, "x": None},
        ):
            result = parse(replace_note(self.main_image(source)))
            self.assertEqual(
                result["g"]["x"], {"v": 1, "s": "custom", "h": html_note()}
            )
            self.assertEqual(result["g"]["v"], plain_note())
            self.assertNotIn("e", result["g"])

    def test_upsert_preserves_unrelated_raw_tokens(self):
        raw = b'{ "g": {"a":"none","unknown":1e+03,"escaped":"\\u0061" \n}, "other":"\\/"}'
        result = replace_note(raw)
        self.assertIn(b'"unknown":1e+03', result)
        self.assertIn(b'"escaped":"\\u0061"', result)
        self.assertIn(b'"other":"\\/"', result)
        self.assertIn(b" \n,", result)

    def test_unknown_versions_rejected(self):
        for version in (2, True):
            with self.assertRaises(ValueError):
                replace_note(
                    self.main_image(
                        {"a": "none", "x": {"v": version, "s": "custom", "h": ""}}
                    )
                )

    def test_links_assets_and_json_single_encoding(self):
        for lang in ("es", "en"):
            html = html_note(lang)
            parser = LinksParser()
            parser.feed(html)
            self.assertEqual(set(parser.links), set(LINKS.values()))
            self.assertFalse(parser.bad)
            self.assertFalse(
                {"script", "iframe", "form", "img", "link", "style"} & set(parser.tags)
            )
            self.assertIn("Ghost Developer", html)
            self.assertIn("Ghost Nexora Studio", html)
            self.assertNotIn("Phantom", html)
            self.assertNotIn("HABIBI", html)
            path = (
                Path(__file__).resolve().parents[1]
                / "notes"
                / f"spdecode-note.{lang}.json"
            )
            self.assertEqual(json.loads(path.read_text()), html)

    def test_notes_only_rewrap_keeps_profile_ciphertext(self):
        raw = image(opened=True)
        result, report = with_html_note(raw)
        before, after = codec.open_envelope(raw), codec.open_envelope(result)
        self.assertEqual(before["j"], after["j"])
        self.assertEqual(codec.decrypt(raw)["config"], codec.decrypt(result)["config"])
        main = codec.decrypt(result)["main"]
        self.assertEqual(main["g"]["x"]["h"], html_note())
        self.assertEqual(main["g"]["a"], "none")
        self.assertTrue(main["g"]["c"])
        self.assertTrue(report["profile_ciphertext_byte_identical"])

    def test_missing_note_in_real_envelope_can_be_inserted(self):
        raw = image(opened=True)
        env = codec.open_envelope(raw)
        key, aad = codec.derive(env, None, None)
        main = codec.decrypt(raw)["main"]
        main["g"].pop("v")
        env["i"]["b"], env["i"]["c"] = seal(
            key, aad + b"\0m", json.dumps(main).encode()
        )
        nonce, cipher = seal(codec.OUTER_KEY, codec.OUTER_AAD, json.dumps(env).encode())
        result, _ = with_html_note(bytes.fromhex(nonce + cipher))
        self.assertEqual(codec.decrypt(result)["main"]["g"]["x"]["h"], html_note())


if __name__ == "__main__":
    unittest.main()
