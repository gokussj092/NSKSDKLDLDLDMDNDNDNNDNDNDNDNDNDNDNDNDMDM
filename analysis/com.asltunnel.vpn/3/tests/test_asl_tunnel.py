"""Pytest suite for the ASL TUNNEL 3.0 integration.

Synthetic fixtures only (no network, no secrets, no keys in this file:
the fixtures are ciphertext produced with the verified method, and the
decoders under test hold the method). Run from the repo root:

  python3 -m pytest analysis/com.asltunnel.vpn/3/tests/test_asl_tunnel.py -v
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
APP_DIR = os.path.join(ROOT, "decoders", "Python", "apps", "ASL_Tunnel")
sys.path.insert(0, APP_DIR)

import server_catalog_decoder  # noqa: E402
import file_decoder  # noqa: E402
from asltunnel import decode_asl_file, decode_asl_text, encode_asl  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def test_plain_asl_decodes():
    doc, notes = decode_asl_file(os.path.join(FIXTURES, "test_plain.asl"))
    assert doc["Server"] == "Test Server 1"
    assert doc["ProxyPort"] == "80"
    assert doc["ExpireDate"] == 1893456000000
    assert doc["SNIHost"] == "www.example.com"


def test_server_asl_decodes():
    doc, _notes = decode_asl_file(os.path.join(FIXTURES, "test_server.asl"))
    assert doc["Name"] == "My Custom Server"
    assert doc["ServerIPHost"] == "example.com;1.2.3.4"
    assert doc["Username"] == "user1"
    assert doc["V2ray"]["UUID"] == "438e4a99-7587-abb5-47b6-fa49b377b061"
    assert doc["SlowDNS"]["DNSTTNS"] == "dnsde1.dozapp.xyz"


def test_password_shape_reported():
    doc = {"Server": "Locked", "ProxyPort": "80", "ExpireDate": 0,
           "isPassON": True, "MyPass": "secret123"}
    blob = encode_asl(doc)
    back, notes = decode_asl_text(blob)
    assert back["isPassON"] is True
    assert back["MyPass"] == "secret123"
    assert any("password required" in n for n in notes)


def test_file_decoder_cli():
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         os.path.join(FIXTURES, "test_plain.asl")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["Server"] == "Test Server 1"
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         os.path.join(FIXTURES, "test_server.asl")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["V2ray"]["UUID"] == "438e4a99-7587-abb5-47b6-fa49b377b061"


def test_invalid_asl_rejected():
    with pytest.raises(ValueError):
        decode_asl_file(os.path.join(FIXTURES, "invalid.asl"))
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         os.path.join(FIXTURES, "invalid.asl")],
        capture_output=True, text=True)
    assert proc.returncode == 1
    assert proc.stdout == ""


def test_empty_input_rejected():
    with pytest.raises((ValueError, TypeError)):
        server_catalog_decoder.run(b"")
    with pytest.raises(ValueError):
        decode_asl_text("   ")
