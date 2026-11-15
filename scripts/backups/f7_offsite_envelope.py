#!/usr/bin/env python3
"""F7-RECOVERY-P01: streaming off-site X25519+AES-256-GCM backup envelope.

NO automatic backups or Supabase requests. Only 'seal' needs a public key.
Private recipient key must be generated and retained OFF the VPS/Supabase,
preferably with a second encrypted offline recovery copy.

Never log plaintext, passwords, secrets or private keys.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"SPDECODE_OFFSITE_V1\n"
EPHEMERAL_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + EPHEMERAL_LEN + NONCE_LEN
CHUNK = 256 * 1024
INFO = b"spdecode:offsite:backup:v1:x25519:aes256gcm"


class BackupError(ValueError):
    pass


def generate_recovery_keys(private_path: Path, public_path: Path) -> None:
    """Run only on an independent trusted machine, NOT on the VPS."""
    if private_path.resolve() == public_path.resolve():
        raise BackupError("Private/public file paths must be different")
    private_key = X25519PrivateKey.generate()
    private_data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_data = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    paths = (private_path, public_path)
    if any(p.is_symlink() or p.exists() for p in paths):
        raise BackupError("Refusing to overwrite key files")
    created = []
    try:
        for path, data in zip(paths, (private_data, public_data)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
    except Exception:
        for item in created:
            item.unlink(missing_ok=True)
        raise


def _derive(shared: bytes, ephemeral_public: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=hashlib.sha256(MAGIC + ephemeral_public).digest(),
                info=INFO).derive(shared)


def _staged(output: Path):
    if output.is_symlink() or output.exists():
        raise BackupError("Output path exists; snapshots must be immutable")
    if not output.parent.is_dir():
        raise BackupError("Output directory missing")
    handle = tempfile.NamedTemporaryFile(mode="w+b", prefix=".spdecode-backup-",
                                         dir=output.parent, delete=False)
    os.chmod(handle.name, 0o600)
    return handle


def _commit(handle, output: Path):
    handle.flush()
    os.fsync(handle.fileno())
    handle.close()
    # Atomic publication without overwriting any existing snapshot.
    os.link(handle.name, output)
    os.unlink(handle.name)
    if hasattr(os, "O_DIRECTORY"):
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _safe_paths(input_path: Path, output: Path):
    if input_path.is_symlink() or not input_path.is_file():
        raise BackupError("Input must be an existing regular file")
    if input_path.resolve() == output.resolve():
        raise BackupError("Input and output cannot be the same file")


def seal(input_path: Path, output: Path, recipient_public_pem: bytes) -> str:
    _safe_paths(input_path, output)
    recipient = serialization.load_pem_public_key(recipient_public_pem)
    if not isinstance(recipient, X25519PublicKey):
        raise BackupError("Only X25519 recipient public keys accepted")
    ephemeral = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = MAGIC + ephemeral_pub + nonce
    key = _derive(ephemeral.exchange(recipient), ephemeral_pub)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    handle = _staged(output)
    try:
        digest = hashlib.sha256()
        with open(input_path, "rb") as source:
            handle.write(header)
            digest.update(header)
            while True:
                raw = source.read(CHUNK)
                if not raw:
                    break
                encrypted = cipher.update(raw)
                handle.write(encrypted)
                digest.update(encrypted)
        tail = cipher.finalize()
        handle.write(tail)
        handle.write(cipher.tag)
        digest.update(tail)
        digest.update(cipher.tag)
        _commit(handle, output)
        return digest.hexdigest()
    finally:
        if not handle.closed:
            handle.close()
        Path(handle.name).unlink(missing_ok=True)


def unseal(source_path: Path, output: Path, recipient_private_pem: bytes) -> None:
    _safe_paths(source_path, output)
    private = serialization.load_pem_private_key(recipient_private_pem, password=None)
    if not isinstance(private, X25519PrivateKey):
        raise BackupError("Only X25519 recipient private keys accepted")
    size = source_path.stat().st_size
    if size < HEADER_LEN + TAG_LEN:
        raise BackupError("Truncated ciphertext")
    handle = _staged(output)
    try:
        with open(source_path, "rb") as source:
            header = source.read(HEADER_LEN)
            if len(header) != HEADER_LEN or not header.startswith(MAGIC):
                raise BackupError("Invalid envelope header")
            ephemeral = header[len(MAGIC):len(MAGIC)+EPHEMERAL_LEN]
            nonce = header[-NONCE_LEN:]
            source.seek(size - TAG_LEN)
            tag = source.read(TAG_LEN)
            key = _derive(private.exchange(X25519PublicKey.from_public_bytes(ephemeral)),
                          ephemeral)
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
            cipher.authenticate_additional_data(header)
            source.seek(HEADER_LEN)
            remaining = size - HEADER_LEN - TAG_LEN
            while remaining:
                data = source.read(min(CHUNK, remaining))
                if not data:
                    raise BackupError("Truncated ciphertext")
                remaining -= len(data)
                handle.write(cipher.update(data))
            # Authentication MUST succeed before publishing decrypted plaintext.
            handle.write(cipher.finalize())
        _commit(handle, output)
    finally:
        if not handle.closed:
            handle.close()
        Path(handle.name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    p = subs.add_parser("genkey", help="ONLY ON AN OFF-VPS trusted computer")
    p.add_argument("--private-out", required=True, type=Path)
    p.add_argument("--public-out", required=True, type=Path)
    for name in ("seal", "unseal"):
        q = subs.add_parser(name)
        q.add_argument("--input", required=True, type=Path)
        q.add_argument("--output", required=True, type=Path)
        q.add_argument("--recipient-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "genkey":
            generate_recovery_keys(args.private_out, args.public_out)
        elif args.command == "seal":
            digest = seal(args.input, args.output, args.recipient_key.read_bytes())
            print("Sealed off-site snapshot; ciphertext SHA256=" + digest)
        else:
            unseal(args.input, args.output, args.recipient_key.read_bytes())
            print("Authenticated restore completed")
    except Exception as exc:
        # Avoid logging paths, key data, encryption payloads or exception text.
        print("Backup operation failed: " + type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
