#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sobre generico Argon2id + AES-256-GCM (SIN claves de formato).

Misma construccion que el metodo DeepTune-VPN: Base64(salt[0:16] ||
nonce[16:28] || ciphertext[28:]), Argon2id + AES-256-GCM, AAD = salt.
La contrasena se recibe como parametro: los tests usan claves de
prueba sinteticas. Las contrasenas reales viven unicamente en los
scripts operativos y nunca aparecen aqui.
"""
import base64

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def argon2_key(password, salt, time_cost=3, memory_kib=8192, parallelism=1):
    return hash_secret_raw(
        secret=password, salt=salt,
        time_cost=time_cost, memory_cost=memory_kib, parallelism=parallelism,
        hash_len=32, type=Type.ID,
    )


def encrypt_blob(plaintext, password, salt=None, nonce=None,
                 time_cost=3, memory_kib=8192, parallelism=1):
    """plaintext (bytes) -> Base64(salt || nonce || ct)."""
    import os
    salt = salt if salt is not None else os.urandom(16)
    nonce = nonce if nonce is not None else os.urandom(12)
    key = argon2_key(password, salt, time_cost, memory_kib, parallelism)
    ct = AESGCM(key).encrypt(nonce, plaintext, salt)
    return base64.b64encode(salt + nonce + ct).decode("ascii")


def decrypt_blob(blob_b64, password,
                 time_cost=3, memory_kib=8192, parallelism=1):
    """Base64(salt || nonce || ct) -> plaintext (bytes)."""
    raw = base64.b64decode(blob_b64)
    if len(raw) < 44:
        raise ValueError("sobre demasiado corto")
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = argon2_key(password, salt, time_cost, memory_kib, parallelism)
    return AESGCM(key).decrypt(nonce, ct, salt)


def aes_gcm_decrypt(raw, password,
                    time_cost=3, memory_kib=8192, parallelism=1):
    """raw = salt[0:16] || nonce[16:28] || ciphertext[28:], AAD = salt."""
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    key = argon2_key(password, salt, time_cost, memory_kib, parallelism)
    return AESGCM(key).decrypt(nonce, ct, salt)
