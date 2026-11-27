#!/usr/bin/env python3
"""Dossier tests for STLRAY 1.1.36 (synthetic fixtures only).

Run from the repo root (or from this stage root, which mirrors it):
    <venv>/bin/python -m pytest \
        analysis/com.stlray.thvpn/36/tests/test_stlray.py -v

Fixtures hold ciphertext envelopes + synthetic plaintexts only
(example.invalid hosts, fake users). No keys, no real credentials,
no live catalog bytes.
"""
import base64
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from decoders.Python.apps.STLRAY import file_decoder  # noqa: E402
from decoders.Python.apps.STLRAY import server_catalog_decoder as bridge  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def _expected_profile():
    return json.loads((FIX / "tvc-profile-expected.json").read_text())


def test_tvc_link_normal():
    link = (FIX / "tvc-sray-link.txt").read_text().strip()
    assert link.startswith("sray://")
    assert json.loads(file_decoder.decode_text(link)) == _expected_profile()
    assert file_decoder.decode(link) == _expected_profile()


def test_tvc_link_locked():
    link = (FIX / "tvc-sray-locked-link.txt").read_text().strip()
    assert json.loads(file_decoder.decode_text(link)) == _expected_profile()


def test_tvc_raw_bytes():
    raw = base64.urlsafe_b64decode(
        (FIX / "tvc-sray-raw.b64").read_text().strip())
    assert file_decoder.decode(raw) == _expected_profile()


def test_tvc_unknown_scheme_is_none():
    assert file_decoder.decode_text("vmess://AAAA") is None
    assert file_decoder.decode_text("not a link") is None


def test_tvc_negative_truncated_and_garbage():
    for bad in (b"", b"\x00\x01\x02", b"AAAA"):
        try:
            file_decoder.decode(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad input must fail: {bad!r}")


def test_catalog_bundle_merges_three_sources():
    bundle = (FIX / "catalog-bundle.json").read_bytes()
    out = json.loads(bridge.run(bundle))
    expected = json.loads((FIX / "catalog-expected.json").read_text())
    assert out == expected
    assert "updates" not in out
    assert out["modes"]["modes"][0]["name"] == "SYNTHETIC MODE"
    assert out["policy"] == {"revision": 1, "configVersion": 0.1,
                             "rules": []}


def test_catalog_single_envelope():
    env = (FIX / "catalog-config-only.json").read_bytes()
    out = json.loads(bridge.run(env))
    assert out["revision"] == 1
    assert "updates" not in out
    assert "modes" not in out


def test_catalog_rejects_bad_bundle():
    for bad in (b"not json", b'{"kind":"wrong","catalogs":{}}',
                b'{"kind":"spdecode-stlray-vpn-catalogs-v1",'
                b'"catalogs":{"config":"@@@"}}'):
        try:
            bridge.run(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad bundle must fail: {bad[:40]!r}")


def test_bridge_result_has_no_download_api():
    bundle = (FIX / "catalog-bundle.json").read_bytes()
    rendered = bridge.run(bundle)
    assert "stallionray.my.id" not in rendered
    assert "updates" not in rendered
    assert "configLocator" not in rendered
