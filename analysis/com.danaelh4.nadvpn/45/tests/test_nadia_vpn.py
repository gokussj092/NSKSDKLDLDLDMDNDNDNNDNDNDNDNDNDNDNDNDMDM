"""Pytest suite for the NadiaVPN 1.4.6 integration (synthetic fixtures
only, plus an optional real-sample check).

Run from the repo root:
  python3 -m pytest tests/test_nadia_vpn.py -v

Optional real-sample check (NOT run by default; the real link is never
stored in this repo):
  NADIA_REAL_SAMPLE=/path/to/sample-nad-sec2.txt python3 -m pytest tests/test_nadia_vpn.py -v -k real_sample
The sample must open with a verified HMAC and a complete JSON profile.
"""
import base64
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(ROOT, "decoders", "Python", "apps", "NadiaVPN")
sys.path.insert(0, APP_DIR)

import file_decoder  # noqa: E402
from file_decoder import NadiaDecodeError, decode, decode_text  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "golden", "nadia_vectors.json")


def load_vectors():
    with open(VECTORS, encoding="utf-8") as fh:
        return json.load(fh)


def test_golden_v2_file():
    vec = load_vectors()
    raw = (vec["v2"]["prefix"] + vec["v2"]["b64"]).encode()
    assert decode(raw) == vec["profile"]


def test_golden_pw2_file_password_flow():
    vec = load_vectors()
    raw = (vec["pw2"]["prefix"] + vec["pw2"]["b64"]).encode()
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(raw)
    assert excinfo.value.code == "PASSWORD_REQUIRED"
    assert decode(raw, password=vec["pw2"]["password"]) == vec["profile"]
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(raw, password="wrong")
    assert excinfo.value.code == "AUTH_FAILED"


def test_golden_binary_envelope():
    vec = load_vectors()
    blob = base64.b64decode(vec["binary_b64"])
    assert decode(blob)["Name"] == "Synthetic Test"


def test_golden_sec2_and_pw2_links():
    vec = load_vectors()
    assert json.loads(decode_text(vec["sec2_link"])) == vec["profile"]
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode_text(vec["pw2_link"])
    assert excinfo.value.code == "PASSWORD_REQUIRED"
    assert json.loads(decode_text(vec["pw2_link"],
                                  password=vec["pw2"]["password"])) == vec["profile"]
    assert decode_text("vmess://AAAA") is None
    assert json.loads(decode_text("nad://{\"Name\": \"Synthetic Test\"}"))["Name"] == "Synthetic Test"


def test_fresh_roundtrip_v2_pw2_binary():
    profile = {"Name": "Fresh", "ServerIP": "example.invalid",
               "ServerPort": "443", "Protocol": "SSL"}
    payload = json.dumps(profile).encode()
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE properties SYSTEM '
        '"http://java.sun.com/dtd/properties.dtd">\n'
        "<properties>\n"
        '<entry key="Name">Fresh</entry>\n'
        '<entry key="ServerIP">example.invalid</entry>\n'
        "</properties>\n"
    ).encode()
    blob = file_decoder._encrypt_v2(xml)
    assert decode(b"NADIA_SEC_V2:" + base64.b64encode(blob)) == {
        "Name": "Fresh", "ServerIP": "example.invalid"}
    assert decode(blob) == {"Name": "Fresh", "ServerIP": "example.invalid"}
    blob_pw = file_decoder._encrypt_v2(xml, password="test123")
    assert decode(b"NADIA_SEC_PW2:" + base64.b64encode(blob_pw),
                  password="test123")["Name"] == "Fresh"
    link = "nad://sec2:" + base64.b64encode(
        file_decoder._encrypt_v2(payload)).decode()
    assert json.loads(decode_text(link)) == profile


def test_negative_cases():
    vec = load_vectors()
    bad = bytearray(base64.b64decode(vec["binary_b64"]))
    bad[-1] ^= 0x01
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(bytes(bad))
    assert excinfo.value.code == "DECODE_FAILED"
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(b"NADIA_SEC_V1:AAAA")
    assert excinfo.value.code == "UNSUPPORTED_VERSION"
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(b"NADIA_SEC_HWID:AAAA")
    assert excinfo.value.code == "HWID_REQUIRED"
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(b"NADIA_SEC_HWID:AAAA", hwid="00" * 32)
    assert excinfo.value.code == "UNSUPPORTED_VARIANT"
    with pytest.raises(NadiaDecodeError) as excinfo:
        decode(b"NADIA_SEC_HWID_PW:AAAA")
    assert excinfo.value.code == "HWID_PASSWORD_REQUIRED"
    with pytest.raises(NadiaDecodeError):
        decode(b"not a nad file at all, far too short")
    with pytest.raises(NadiaDecodeError):
        decode(b"")


def test_cli_self_test_and_file():
    proc = subprocess.run(
        [sys.executable, os.path.join(APP_DIR, "file_decoder.py"),
         "--self-test"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert "self-test OK" in proc.stdout
    vec = load_vectors()
    path = os.path.join(HERE, "golden", "nadia_vectors.json")
    assert os.path.isfile(path)
    # CLI over a .nad file (prefixed text), no stdin credentials.
    import tempfile
    raw = (vec["v2"]["prefix"] + vec["v2"]["b64"]).encode()
    with tempfile.NamedTemporaryFile(suffix=".nad", delete=False) as fh:
        fh.write(raw)
        tmp = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, os.path.join(APP_DIR, "file_decoder.py"), tmp],
            capture_output=True, text=True, timeout=120,
            stdin=subprocess.DEVNULL)
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout)["ServerIP"] == "example.invalid"
    finally:
        os.unlink(tmp)


def test_engine_and_text_bridge_routes():
    sys.path.insert(0, ROOT)
    from cloud.workers.python.engine import decode_file, load_runtime_file_engines
    from cloud.workers.python import text_bridge
    extended = load_runtime_file_engines()
    assert extended["nad"]["name"] == "NadiaVPN 1.4.6"
    assert extended["nad"]["phase"] == "C8"
    vec = load_vectors()
    raw = (vec["v2"]["prefix"] + vec["v2"]["b64"]).encode()
    out = decode_file("nad", raw)
    assert out["status"] == "success"
    assert out["structuredJson"]["ServerIP"] == "example.invalid"
    out = text_bridge.dispatch(vec["sec2_link"])
    assert json.loads(out) == vec["profile"]
    # The supplied loader imports the module under its own name, so the
    # raised class is not identical to the directly imported one:
    # assert on the worker error code, not the class.
    try:
        text_bridge.dispatch(vec["pw2_link"])
    except Exception as exc:
        assert getattr(exc, "code", None) == "PASSWORD_REQUIRED", exc
    else:
        raise AssertionError("pw2 link without password must fail")
    out = text_bridge.dispatch(vec["pw2_link"], password="test123")
    assert json.loads(out) == vec["profile"]


@pytest.mark.real_sample
def test_real_sample_opens():
    sample = os.environ.get("NADIA_REAL_SAMPLE")
    if not sample or not os.path.isfile(sample):
        pytest.skip("NADIA_REAL_SAMPLE not set")
    with open(sample, encoding="utf-8") as fh:
        text = fh.read().strip()
    assert text.startswith("nad://sec2:")
    doc = json.loads(decode_text(text))
    # The real sample is a test profile; assert shape, not values.
    assert isinstance(doc, dict) and len(doc) >= 20
    for key in ("Name", "ServerIP", "ServerPort", "Protocol",
                "SSHUser", "SSHPass", "SNI", "Payload", "nadiaSig"):
        assert key in doc, key
    assert doc["nadiaSig"] == "NADIA_SEC_OK"
