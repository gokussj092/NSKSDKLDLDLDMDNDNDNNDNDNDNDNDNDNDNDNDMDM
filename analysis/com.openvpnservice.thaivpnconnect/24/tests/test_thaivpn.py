#!/usr/bin/env python3
"""Dossier tests for ThaiVPN Connect 2.4 (synthetic fixtures only).

Run from the repo root (or from this stage root, which mirrors it):
    <venv>/bin/python -m pytest \
        analysis/com.openvpnservice.thaivpnconnect/24/tests/test_thaivpn.py -v

Fixtures hold one synthetic XXTEA blob + the expected decoded
catalog (example.invalid hosts, fake users). No keys, no real
credentials, no live catalog bytes.
"""
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from decoders.Python.apps.ThaiVPN_Connect import file_decoder  # noqa: E402
from decoders.Python.apps.ThaiVPN_Connect import server_catalog_decoder as bridge  # noqa: E402
from decoders.Python.apps.ThaiVPN_Connect import thaivpn  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def _expected():
    return json.loads((FIX / "catalog-expected.json").read_text())


def test_profile_fixture_decodes():
    blob = (FIX / "profile.json").read_bytes()
    assert file_decoder.decode(blob) == _expected()
    assert json.loads(file_decoder.run(blob)) == _expected()


def test_catalog_bridge_accepts_same_blob():
    blob = (FIX / "profile.json").read_bytes()
    assert json.loads(bridge.run(blob)) == _expected()


def test_profile_round_trip_encrypt():
    catalog = _expected()
    blob = thaivpn.encrypt_blob(catalog)
    assert thaivpn.decode_catalog(thaivpn.decrypt_blob(blob)) == catalog


def test_no_leftover_encoded_values():
    assert thaivpn.find_leftover_encoded(_expected()) == []


def test_negative_truncated_and_garbage():
    for bad in ("", "AAAA", "!!!not-base64!!!"):
        try:
            file_decoder.decode(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"bad input must fail: {bad!r}")
    try:
        bridge.run(b"")
    except ValueError:
        pass
    else:
        raise AssertionError("empty catalog must fail")


def test_bridge_result_has_no_download_api():
    blob = (FIX / "profile.json").read_bytes()
    rendered = bridge.run(blob)
    assert "thaivapp.my.id" not in rendered
    assert "decryptionStatus" not in rendered  # complete: no leftovers
