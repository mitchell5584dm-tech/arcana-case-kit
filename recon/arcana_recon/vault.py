"""ARCN vault blobs, byte-compatible with the Rust ``arcana-vault`` crate.

Layout: ``ARCN | version(1) | salt(16) | nonce(12) | ciphertext+tag``.

Two key-derivation versions exist, told apart by the version byte:

* **v0x02 (current default)** — Argon2id, 64 MiB memory, 3 iterations,
  4 lanes, 32-byte key, Argon2 version 0x13. Identical parameters to the
  Rust crate's v0x02 and to the master bundle's v0x02, so v0x02 blobs are
  mutually readable across all three.
* **v0x01 (legacy)** — 100,000 rounds of SHA-256 over
  ``acc || salt || round_le32``, seeded by
  ``SHA-256(passphrase || salt || domain)``. This is the repo's own v1
  KDF, kept readable for blobs sealed before the Argon2id migration. It
  is NOT the same KDF as the master bundle's v0x01 (same version byte,
  different derivation). Nothing in this package seals v0x01 any more.

Nothing about the key is ever written to disk or returned to callers;
anyone holding the passphrase can unseal the blob in any process, with
either this module or ``arcana-acquire verify``.
"""
from __future__ import annotations

import hashlib
import os

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"ARCN"
VERSION_V1 = 1
VERSION_V2 = 2
# New seals are v0x02; VERSION is kept as the current default for callers
# (engine.py reports it in the report JSON).
VERSION = VERSION_V2
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN
STRETCH_ROUNDS = 100_000
DOMAIN = b"arcana-vault-kdf-v1"
MIN_PASSPHRASE_LEN = 12

# Argon2id parameters for v0x02 — must match the Rust crate exactly:
# 64 MiB memory, 3 iterations, 4 lanes, 32-byte key, Argon2 version 0x13.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_VERSION = 19  # 0x13

KDF_DESCRIPTION = "argon2id-64MiB-3iter-4lanes"
KDF_DESCRIPTION_V1 = f"sha256-stretch-{STRETCH_ROUNDS}"


class VaultError(Exception):
    """The blob is malformed, the passphrase is wrong, or the data was modified."""


def check_passphrase(passphrase: str) -> bytes:
    # The Rust crate checks byte length (str::len), so compare the UTF-8 length too.
    pw = passphrase.encode("utf-8")
    if len(pw) < MIN_PASSPHRASE_LEN:
        raise VaultError(f"passphrase must be at least {MIN_PASSPHRASE_LEN} characters")
    return pw


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Legacy v0x01 derivation (repo KDF, domain ``arcana-vault-kdf-v1``).

    Kept so old blobs still open. Nothing seals v0x01 any more.
    """
    pw = check_passphrase(passphrase)
    if len(salt) != SALT_LEN:
        raise VaultError("salt must be 16 bytes")
    acc = hashlib.sha256(pw + salt + DOMAIN).digest()
    for round_id in range(STRETCH_ROUNDS):
        acc = hashlib.sha256(acc + salt + round_id.to_bytes(4, "little")).digest()
    return acc


def derive_key_v2(passphrase: str, salt: bytes) -> bytes:
    """Current v0x02 derivation: Argon2id, parameters identical to the
    Rust crate's v0x02 (64 MiB / 3 iter / 4 lanes / V0x13)."""
    pw = check_passphrase(passphrase)
    if len(salt) != SALT_LEN:
        raise VaultError("salt must be 16 bytes")
    return hash_secret_raw(
        secret=pw,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Argon2Type.ID,
        version=ARGON2_VERSION,
    )


def _seal_with_version(plaintext: bytes, passphrase: str, version: int) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    if version == VERSION_V1:
        key = derive_key(passphrase, salt)
    elif version == VERSION_V2:
        key = derive_key_v2(passphrase, salt)
    else:
        raise VaultError(f"unsupported vault version {version}")
    body = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + bytes([version]) + salt + nonce + body


def seal(plaintext: bytes, passphrase: str) -> bytes:
    """Seals with the current default: ARCN v0x02 (Argon2id)."""
    return _seal_with_version(plaintext, passphrase, VERSION_V2)


def seal_v1(plaintext: bytes, passphrase: str) -> bytes:
    """Seals with the legacy v0x01 KDF. Only for reproducing old blobs in
    tests; nothing in the package seals v0x01 any more."""
    return _seal_with_version(plaintext, passphrase, VERSION_V1)


def unseal(blob: bytes, passphrase: str) -> bytes:
    """Opens an ARCN blob of either version: v0x01 with the legacy
    SHA-256 KDF, v0x02 with Argon2id. Any other version byte, bad magic,
    truncation, wrong passphrase, or tampered byte raises VaultError."""
    if len(blob) < HEADER_LEN + TAG_LEN:
        raise VaultError("blob too short")
    if blob[:4] != MAGIC:
        raise VaultError("bad magic: not an ARCN vault blob")
    version = blob[4]
    salt = blob[5:5 + SALT_LEN]
    nonce = blob[5 + SALT_LEN:HEADER_LEN]
    if version == VERSION_V1:
        key = derive_key(passphrase, salt)
    elif version == VERSION_V2:
        key = derive_key_v2(passphrase, salt)
    else:
        raise VaultError(f"unsupported vault version {version}")
    try:
        return AESGCM(key).decrypt(nonce, blob[HEADER_LEN:], None)
    except InvalidTag:
        raise VaultError("authentication failed: wrong passphrase or modified blob") from None
