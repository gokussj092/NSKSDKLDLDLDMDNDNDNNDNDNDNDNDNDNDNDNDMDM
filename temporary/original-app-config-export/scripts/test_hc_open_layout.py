#!/usr/bin/env python3
"""Synthetic data-loss/authentication regressions for the reference-backed lab."""

import copy
import json
import struct
import unittest

from hc_open_layout_experiment import (
    convert,
    codec,
    hc,
    seal,
    parse,
    unpack_profile,
    options_span,
    connection_view,
)
from audit_hc_matrix import authenticate_pure


def image(*, opened=False, conflict=False, extra_sidecar_metadata=False):
    features = ["ssh", "profiles"] if opened else ["ssh"]
    main = {
        "s": 4,
        "t": 1700000000,
        "c": features,
        "g": {
            "a": "none" if opened else "lock_all",
            "v": "Synthetic note",
            "c": True,
            "d": 1900000000,
            "f": False,
            "g": [],
        },
        "u": "https://example.invalid/update",
        "r": 300,
        "unknown": {"keep": [False, 0, None]},
    }
    env = {
        "a": "HCCFG",
        "b": 10,
        "c": "s1",
        "d": "h1",
        "e": "n11",
        "f": features,
        "g": bytes(range(32)).hex(),
        "h": 0,
        "n": 899,
        "unknown": {"nested": [1, False, None]},
    }
    key, aad = codec.derive(env, None, None)
    nonce, cipher = seal(key, aad + b"\0m", json.dumps(main).encode())
    env["i"] = {"a": "m", "b": nonce, "c": cipher, "unknown": "keep"}
    payload = "GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n"
    options = json.dumps(
        {
            "customPayload": "DIFFERENT" if conflict else payload if opened else "",
            "nested": {"keep": [True, 0, None]},
            "sni": "",
        },
        indent=1,
    ).encode()
    options = options[:-2] + b', "number":1e+03\n}'

    def text(value):
        data = value.encode()
        return struct.pack(">I", len(data)) + data

    raw = (
        b"HPC1"
        + struct.pack(">I", 11)
        + text("Synthetic")
        + text("ssh")
        + text("example.invalid")
        + struct.pack(">I", 443)
        + text("demo")
        + text("dummy")
        + text("")
        + struct.pack(">I", len(options))
        + options
        + struct.pack(">IQ", 123, 1700000000)
        + text("0")
    )
    if not opened:
        nonce, ct = seal(key, aad + b"\0s0:r", raw)
        raw = b"HPR1" + bytes.fromhex(nonce + ct)
    nonce, ct = seal(key, aad + b"\0s0", raw)
    section = {"a": "s0", "b": nonce, "c": ct, "unknown": {"value": [0, False]}}
    if not opened:
        nonce, ct = seal(key, aad + b"\0s0:x", payload.encode())
        section["d"] = {"a": nonce, "b": ct}
        if extra_sidecar_metadata:
            section["d"]["unknown"] = "keep"
    env["j"] = [section]
    nonce, ct = seal(codec.OUTER_KEY, codec.OUTER_AAD, json.dumps(env).encode())
    return bytes.fromhex(nonce + ct).decode("latin-1").encode("utf-8")


class OpenLayoutTests(unittest.TestCase):
    def test_full_migration_rekeys_preserves_data_and_expiry(self):
        source, reference = image(), image(opened=True)
        result, report = convert(source, reference)
        before, after = codec.decrypt(source), codec.decrypt(result)
        self.assertEqual(after["main"]["g"]["a"], "none")
        self.assertTrue(after["main"]["g"]["c"])
        self.assertEqual(after["main"]["g"]["d"], before["main"]["g"]["d"])
        self.assertEqual(connection_view(before), connection_view(after))
        env = codec.open_envelope(result)
        key, aad = codec.derive(env, None, None)
        plain = hc._dec_section(env["j"][0], key, aad)
        self.assertTrue(plain.startswith(b"HPC1"))
        self.assertNotIn("d", env["j"][0])
        self.assertEqual(env["f"], ["ssh", "profiles"])
        self.assertEqual(env["unknown"], codec.open_envelope(source)["unknown"])
        self.assertEqual(
            env["j"][0]["unknown"], codec.open_envelope(source)["j"][0]["unknown"]
        )
        self.assertEqual(authenticate_pure(result)[2], 3)
        self.assertTrue(report["profiles"][0]["hpr1_removed"])
        self.assertTrue(
            report["profiles"][0]["sidecar_relocated_to_existing_customPayload"]
        )
        # Raw bytes before/after the options string and its unedited numeric
        # token stay intact, independently of the readable decoder projection.
        old_env = codec.open_envelope(source)
        old_key, old_aad = codec.derive(old_env, None, None)
        old, _, _ = unpack_profile(old_env["j"][0], old_key, old_aad)
        a, b, _ = options_span(old)
        c, d, new_opts = options_span(plain)
        self.assertEqual(old[:a], plain[:c])
        self.assertEqual(old[b:], plain[d:])
        self.assertIn(b"1e+03", new_opts)

    def test_combined_changes_only_approved_main_values_and_capabilities(self):
        raw = image()
        out, _ = convert(raw, image(opened=True), combined=True)
        old, new = codec.decrypt(raw)["main"], codec.decrypt(out)["main"]
        self.assertEqual(old.keys(), new.keys())
        self.assertEqual(old["unknown"], new["unknown"])
        self.assertEqual(new["g"].keys(), old["g"].keys())
        for k in old["g"].keys() - {"a", "v"}:
            self.assertEqual(old["g"][k], new["g"][k])

    def test_diagnostics_isolate_hpr_and_features_without_losing_sidecar(self):
        reference = image(opened=True)
        for capabilities in (False, True):
            out, _ = convert(
                image(), reference, add_profiles=capabilities, relocate=False
            )
            env = codec.open_envelope(out)
            key, aad = codec.derive(env, None, None)
            self.assertTrue(hc._dec_section(env["j"][0], key, aad).startswith(b"HPC1"))
            self.assertIn("d", env["j"][0])
            self.assertEqual("profiles" in env["f"], capabilities)
            self.assertEqual(
                connection_view(codec.decrypt(image())),
                connection_view(codec.decrypt(out)),
            )

    def test_conflicting_payload_refused(self):
        with self.assertRaises(ValueError):
            convert(image(conflict=True), image(opened=True))

    def test_unknown_sidecar_metadata_not_deleted(self):
        with self.assertRaises(ValueError):
            convert(image(extra_sidecar_metadata=True), image(opened=True))

    def test_locked_reference_and_open_source_rejected(self):
        with self.assertRaises(ValueError):
            convert(image(), image())
        with self.assertRaises(ValueError):
            convert(image(opened=True), image(opened=True))

    def test_tampering_is_not_repaired(self):
        raw = image()
        bad = raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaises(ValueError):
            convert(bad, image(opened=True))


if __name__ == "__main__":
    unittest.main()
