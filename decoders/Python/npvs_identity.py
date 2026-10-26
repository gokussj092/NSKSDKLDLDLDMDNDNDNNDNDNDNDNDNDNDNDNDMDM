"""NPV 124.0.37 recipient interchange. Private material is never persisted here."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import re
from Crypto.PublicKey import ECC
from Crypto.IO import PKCS8

SCHEMA = "spdecode.npvs.recipient.v1"
MAX_MATERIAL = 16384


def encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def binary(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}", value):
        raise ValueError("Invalid recipient encoding")
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if encode(raw) != value or (size is not None and len(raw) != size):
        raise ValueError("Invalid recipient size")
    return raw


def normalize(value) -> dict:
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_MATERIAL:
            raise ValueError("Recipient material exceeds limit")
        def unique(pairs):
            result = {}
            for k, v in pairs:
                if k in result:
                    raise ValueError("Duplicate recipient member")
                result[k] = v
            return result
        value = json.loads(value, object_pairs_hook=unique)
    if (not isinstance(value, dict) or value.get("schema") != SCHEMA or
            value.get("source") not in ("generated", "captured") or
            value.get("curve") != "P-256" or
            not isinstance(value.get("fingerprint"), str) or
            not re.fullmatch("[a-f0-9]{64}", value["fingerprint"])):
        raise ValueError("Invalid recipient identity")
    common = {"schema", "kind", "source", "curve", "fingerprint"}
    if value.get("kind") == "keypair":
        if set(value) != common | {"publicKey", "privateKey"}:
            raise ValueError("Invalid keypair members")
        public = binary(value["publicKey"], 33)
        private_der = binary(value["privateKey"])
        algorithm, _, _ = PKCS8.unwrap(private_der)
        if algorithm != "1.2.840.10045.2.1":
            raise ValueError("Expected EC PKCS8")
        key = ECC.import_key(private_der)
        if key.curve != "NIST P-256" or not key.has_private():
            raise ValueError("Expected a P-256 private key")
        derived = key.public_key().export_key(format="SEC1", compress=True)
        if not hmac.compare_digest(public, derived):
            raise ValueError("Public/private key mismatch")
        if hashlib.sha256(public).hexdigest() != value["fingerprint"]:
            raise ValueError("Invalid public key fingerprint")
    elif value.get("kind") == "agreement":
        if (set(value) != common | {"fileSha256", "peer", "sharedSecret"} or
                value["source"] != "captured" or
                not isinstance(value["fileSha256"], str) or
                not re.fullmatch("[a-f0-9]{64}", value["fileSha256"])):
            raise ValueError("Invalid file-bound agreement")
        peer = binary(value["peer"], 33)
        ECC.import_key(peer, curve_name="P-256")
        if binary(value["sharedSecret"], 32) == bytes(32):
            raise ValueError("Invalid agreement secret")
    else:
        raise ValueError("Unknown recipient material")
    return dict(value)


def generate() -> dict:
    key = ECC.generate(curve="P-256")
    public = key.public_key().export_key(format="SEC1", compress=True)
    return normalize({"schema": SCHEMA, "kind": "keypair", "source": "generated",
        "curve": "P-256", "publicKey": encode(public),
        "privateKey": encode(key.export_key(format="DER", use_pkcs8=True)),
        "fingerprint": hashlib.sha256(public).hexdigest()})


def agreement(material, raw: bytes, records: list[bytes]):
    identity = normalize(material)
    fp = bytes.fromhex(identity["fingerprint"])
    record = next((r for r in records if hmac.compare_digest(r[:32], fp)), None)
    if record is None:
        raise LookupError("Identity is not a recipient")
    if identity["kind"] == "keypair":
        key = ECC.import_key(binary(identity["privateKey"]))
        peer = ECC.import_key(record[32:65], curve_name="P-256")
        shared = int((peer.pointQ * key.d).x).to_bytes(32, "big")
    else:
        if (identity["fileSha256"] != hashlib.sha256(raw).hexdigest() or
                not hmac.compare_digest(binary(identity["peer"], 33), record[32:65])):
            raise LookupError("Agreement belongs to a different file")
        shared = binary(identity["sharedSecret"], 32)
    return record, shared
