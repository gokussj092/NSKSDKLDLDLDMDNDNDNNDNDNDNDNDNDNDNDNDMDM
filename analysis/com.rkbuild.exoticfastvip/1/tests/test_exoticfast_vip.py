"""Pytest suite for the ExoticFast VIP "Rk1" integration.

Synthetic fixtures only (no network, no secrets, no keys in this file:
the fixtures are ciphertext produced with the verified method, and the
decoders under test hold the method). Run from the repo root:

  python3 -m pytest analysis/com.rkbuild.exoticfastvip/1/tests/test_exoticfast_vip.py -v
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
APP_DIR = os.path.join(ROOT, "decoders", "Python", "apps", "ExoticFast_VIP")
sys.path.insert(0, APP_DIR)

import server_catalog_decoder  # noqa: E402
import file_decoder  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def test_synthetic_rj_decodes():
    blob = open(os.path.join(FIXTURES, "synthetic.rj"), "rb").read()
    out = server_catalog_decoder.run(blob)
    cat = json.loads(out)
    assert cat["Version"] == "9.9-test"
    assert len(cat["Servers"]) == 1
    assert cat["Servers"][0]["Name"] == "Synthetic Test"
    assert cat["Servers"][0]["ServerIPHost"] == "example.invalid"
    assert cat["Servers"][0]["Payload"].startswith("GET / HTTP/1.1")
    assert cat["Networks"][0]["SNIHost"] == "example.invalid"
    assert "OVPNCert" in cat and "SYNTHETIC" in cat["OVPNCert"]


def test_file_decoder_cli():
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         os.path.join(FIXTURES, "synthetic.rj")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    cat = json.loads(proc.stdout)
    assert cat["Version"] == "9.9-test"
    assert cat["Servers"][0]["ServerIPHost"] == "example.invalid"


def test_corrupt_rj_rejected():
    blob = open(os.path.join(FIXTURES, "corrupt.rj"), "rb").read()
    with pytest.raises(server_catalog_decoder.DecodeError):
        server_catalog_decoder.run(blob)
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         os.path.join(FIXTURES, "corrupt.rj")],
        capture_output=True, text=True)
    assert proc.returncode == 1
    assert proc.stdout == ""


def test_empty_input_rejected():
    with pytest.raises(server_catalog_decoder.DecodeError):
        server_catalog_decoder.run(b"")
    with pytest.raises(server_catalog_decoder.DecodeError):
        server_catalog_decoder.run(b"   ")


def test_result_has_no_download_api():
    blob = open(os.path.join(FIXTURES, "synthetic.rj"), "rb").read()
    cat = json.loads(server_catalog_decoder.run(blob))
    assert not any(k in cat for k in ("update_api", "auth_api", "notice_api"))
