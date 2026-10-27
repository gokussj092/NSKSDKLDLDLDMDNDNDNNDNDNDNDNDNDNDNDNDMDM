#!/usr/bin/env python3
"""Replace/insert SP-DECODE notes in an existing HC899 file without changing profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from hc_hcx4_n11_experiment import codec, hc, rewrap, private_write
from spdecode_note import replace_note, LANGUAGES
from lossless_json import parse, equal
from audit_hc_matrix import authenticate_pure


def with_html_note(raw, language="es"):
    env = codec.open_envelope(raw)
    key, aad = codec.derive(env, None, None)
    original = codec.decrypt(raw)
    replacement = replace_note(hc._dec_section(env["i"], key, aad), language)
    edited = codec.decrypt(raw)
    edited["main"] = parse(replacement)
    edited["protections"] = hc._norm_prot(edited["main"]["g"])
    output = rewrap(raw, edited, note_language=language)
    final_env, final_main, tags = authenticate_pure(output)
    if final_main != replacement or not equal(final_env["j"], env["j"]):
        raise AssertionError("Note update changed a profile or note bytes")
    if not equal(codec.decrypt(output)["config"], original["config"]):
        raise AssertionError("Connection data changed")
    return output, dict(
        language=language,
        html_field="main.g.x.h",
        plain_fallback_field="main.g.v",
        note_style="custom",
        old_note_policy="REPLACE_ALWAYS",
        profile_ciphertext_byte_identical=True,
        connection_parameters_unchanged=True,
        pure_python_aead_tags_verified=tags,
        original_app_html_rendering="PENDING_MANUAL_TEST",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--language", choices=LANGUAGES, default="es")
    args = parser.parse_args()
    raw = args.source.read_bytes()
    output, record = with_html_note(raw, args.language)
    private_write(args.output, output)
    record.update(
        source_sha256=hashlib.sha256(raw).hexdigest(),
        output_sha256=hashlib.sha256(output).hexdigest(),
        bytes=len(output),
    )
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
