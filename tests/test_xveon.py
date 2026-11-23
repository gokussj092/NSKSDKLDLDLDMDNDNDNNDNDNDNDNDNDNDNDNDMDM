"""Pytest suite for the XVEON Tunnel Pro integration (synthetic fixtures
only, plus an optional live real-link check).

Run from the repo root:
  python3 -m pytest tests/test_xveon.py -v

Optional live check (NOT run by default, needs the real URI out-of-band):
  XVEON_REAL_URI='xveontunnel://...' python3 -m pytest tests/test_xveon.py -v -k real_link
The real URI is never stored in this repo.
"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT, "decoders", "Python", "apps",
                       "XVEON_Tunnel_Pro")
sys.path.insert(0, APP_DIR)

import xveon  # noqa: E402
import file_decoder  # noqa: E402
from file_decoder import XveonDecodeError  # noqa: E402
from xveon import NeedsPassword, XveonError, decrypt_text, summarize  # noqa: E402
from xveon import deobfuscated_constants, encrypt_envelope  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "golden", "xveon_vectors.json")


def load_envelope():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def test_deobfuscated_constants():
    c = deobfuscated_constants()
    assert c["lI"] == "XVN1"
    assert c["ll"] == "AES/GCM/NoPadding"
    assert c["Io"] == "PBKDF2WithHmacSHA256"
    assert c["lo"] == "AES"
    assert c["o"] + c["O"] + c["Il"] == "XveonV7_SshVpn_UltraLite_2026_#Key!"
    # The three URI prefixes are literals in decrypt_text, not Lb1
    # constants: all three must open the same envelope.
    env = load_envelope()
    uri = encrypt_envelope(env)
    body = uri[len("xveontunnel://"):]
    for prefix in ("xveontunnel://", "xveon://", "xvn://"):
        assert decrypt_text(prefix + body) == env


def test_synthetic_envelope_roundtrip():
    env = load_envelope()
    uri = encrypt_envelope(env)
    assert uri.startswith("xveontunnel://XVN1:0:")
    assert decrypt_text(uri) == env
    # bare 5-part string, as stored in a .xveon file
    assert decrypt_text(uri[len("xveontunnel://"):]) == env


def test_synthetic_file_roundtrip(tmp_path):
    env = load_envelope()
    uri = encrypt_envelope(env)
    p = tmp_path / "test.xveon"
    p.write_text(uri[len("xveontunnel://"):], encoding="utf-8")
    assert xveon.decode_file(str(p)) == env
    q = tmp_path / "test.xvn"
    q.write_text(uri, encoding="utf-8")
    assert xveon.decode_file(str(q)) == env


def test_locked_roundtrip_and_wrong_password():
    env = load_envelope()
    uri = encrypt_envelope(env, password="0123456789ABCDEF-extra-long")
    assert uri.split(":")[2] == "1"
    with pytest.raises(NeedsPassword):
        decrypt_text(uri)
    with pytest.raises(XveonError):
        decrypt_text(uri, password="wrong-password")
    assert decrypt_text(uri, password="0123456789ABCDEF-extra-long") == env


def test_tampered_ciphertext_rejected():
    env = load_envelope()
    uri = encrypt_envelope(env)
    parts = uri.split(":")
    tail = parts[4]
    parts[4] = tail[:-4] + ("AAAA" if tail[-4:] != "AAAA" else "BBBB")
    with pytest.raises(XveonError):
        decrypt_text(":".join(parts))


def test_invalid_inputs_rejected():
    for bad in ["", "xveontunnel://XVN1:0:xxx", "XVN1:2:AAAA:AAAA:AAAA",
                "http://example.com/not-xveon"]:
        with pytest.raises(XveonError):
            decrypt_text(bad)


def test_summary_fields():
    env = load_envelope()
    s = summarize(env)
    assert s["profiles"][0]["ssh"]["host"] == "example.test"
    assert s["profiles"][0]["ssh"]["port"] == 443
    assert s["profiles"][0]["proxy"]["host"] == "1.2.3.4"
    assert s["profiles"][1]["xray"]["protocol"] == "VMESS"


def test_file_decoder_document():
    env = load_envelope()
    uri = encrypt_envelope(env)
    doc = file_decoder.decode(uri.encode("utf-8"))
    assert doc["application"] == "XVEON Tunnel Pro 8.1"
    assert doc["protocol"] == "xveontunnel://"
    assert doc["config"] == env
    # bare file content: same envelope, file extension marker
    doc2 = file_decoder.decode(uri[len("xveontunnel://"):])
    assert doc2["extension"] == ".xveon"
    assert doc2["config"] == env
    # run() returns the same document as a JSON string
    assert json.loads(file_decoder.run(uri.encode("utf-8"))) == doc
    # decode_text: the three schemes open, anything else is None
    for prefix in ("xveontunnel://", "xveon://", "xvn://"):
        out = file_decoder.decode_text(prefix + uri[len("xveontunnel://"):])
        assert json.loads(out)["config"] == env
    assert file_decoder.decode_text("vmess://AAAA") is None
    assert file_decoder.decode_text("darktunnel://AAAA") is None
    assert file_decoder.decode_text("") is None


def test_file_decoder_locked_errors():
    env = load_envelope()
    uri = encrypt_envelope(env, password="secret-pw")
    with pytest.raises(XveonDecodeError) as excinfo:
        file_decoder.decode(uri)
    assert excinfo.value.code == "PASSWORD_REQUIRED"
    with pytest.raises(XveonDecodeError) as excinfo:
        file_decoder.decode(uri, password="wrong")
    assert excinfo.value.code == "AUTH_FAILED"
    assert file_decoder.decode(uri, password="secret-pw")["config"] == env
    with pytest.raises(XveonDecodeError) as excinfo:
        file_decoder.decode_text(uri)
    assert excinfo.value.code == "PASSWORD_REQUIRED"


def test_file_decoder_result_has_no_download_apis():
    """Owner rule (2026-11-15): no catalog download APIs in result JSON,
    and none of the forbidden catalog strings in the document."""
    env = load_envelope()
    uri = encrypt_envelope(env)
    doc = file_decoder.decode(uri.encode("utf-8"))
    payload = json.dumps(doc, ensure_ascii=False)
    for forbidden in ("decoders/Python/", '"script":', "source_script",
                      "privateKey", "downloadUrl", "DefUpdateURL"):
        assert forbidden not in payload, forbidden

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert key not in ("url", "apiUrl", "downloadUrl",
                                   "updater", "DefUpdateURL"), key
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)

    list(walk(doc))


def test_file_decoder_cli(tmp_path):
    env = load_envelope()
    uri = encrypt_envelope(env)
    plain = tmp_path / "test.xveon"
    plain.write_text(uri[len("xveontunnel://"):], encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         str(plain)],
        input=b"", capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["config"] == env
    # locked file: no password -> workerError PASSWORD_REQUIRED, exit 3
    locked = tmp_path / "locked.xvn"
    locked.write_text(encrypt_envelope(env, password="secret-pw"),
                      encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         str(locked)],
        input=b"", capture_output=True, timeout=60)
    assert proc.returncode == 3
    assert json.loads(proc.stdout) == {"workerError": "PASSWORD_REQUIRED"}
    # locked file: password on stdin (engine contract) -> opens
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         str(locked)],
        input=json.dumps({"password": "secret-pw"}).encode("utf-8"),
        capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["config"] == env
    # wrong password on stdin -> AUTH_FAILED, exit 3
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         str(locked)],
        input=json.dumps({"password": "nope"}).encode("utf-8"),
        capture_output=True, timeout=60)
    assert proc.returncode == 3
    assert json.loads(proc.stdout) == {"workerError": "AUTH_FAILED"}


@pytest.mark.skipif(not os.environ.get("XVEON_REAL_URI"),
                    reason="needs XVEON_REAL_URI env var (never stored)")
def test_real_link_live():
    env = decrypt_text(os.environ["XVEON_REAL_URI"])
    assert env["v"] == 2 and len(env["profiles"]) == 1
    assert env["profiles"][0]["mode"] == "ssh"
