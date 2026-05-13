"""
AES key-length test corpus for Semgrep rules.

This file intentionally contains both:
  - BAD examples (should be flagged)
  - GOOD examples (should NOT be flagged)

It covers:
  A) Explicit bad lengths (os.urandom / token_bytes / get_random_bytes / KDF length)
  B) External/unknown-length keys flowing into AES without validation (file/env/argv/base64/hex)
  C) Sanitization via explicit length checks (len in {16,24,32})
  D) Optional normalization via slicing to 16/24/32 (include only if your policy allows it)

Note: Some imports (Crypto / cryptography) may not exist in your environment; this is fine
for Semgrep matching. If your IDE complains, add:
  # pyright: reportMissingImports=false
"""

import os
import sys
import base64
import binascii
import secrets
from pathlib import Path


# -------------------------
# Helpers for "external" sources
# -------------------------
def read_key_from_file_bytes(path: str) -> bytes:
    return open(path, "rb").read()  # source: open(...).read()


def read_key_from_env() -> bytes:
    # source: os.getenv / os.environ
    v = os.getenv("APP_AES_KEY", "")
    # common conversion: external string -> bytes (still unknown-length)
    return v.encode("utf-8")


def read_key_from_argv() -> bytes:
    # source: sys.argv[i]
    return sys.argv[1].encode("utf-8") if len(sys.argv) > 1 else b""


def read_key_from_base64(s: str) -> bytes:
    # source: base64.b64decode
    return base64.b64decode(s)


def read_key_from_hex(s: str) -> bytes:
    # source: bytes.fromhex / binascii.unhexlify
    return bytes.fromhex(s)


# -------------------------
# A) Explicit wrong lengths (should be flagged by "bad-explicit-length" rule)
# -------------------------
def explicit_bad_lengths():
    k1 = os.urandom(20)              # BAD: 20 not in {16,24,32}
    k2 = secrets.token_bytes(15)     # BAD: 15
    k3 = secrets.token_bytes(33)     # BAD: 33
    _ = (k1, k2, k3)

    # Optional: PyCryptodome random bytes
    from Crypto.Random import get_random_bytes
    k4 = get_random_bytes(31)        # BAD: 31
    _ = k4


def explicit_good_lengths():
    k1 = os.urandom(16)              # GOOD
    k2 = secrets.token_bytes(24)     # GOOD
    k3 = secrets.token_bytes(32)     # GOOD
    _ = (k1, k2, k3)


# -------------------------
# B) External key -> AES without validation (should be flagged by taint rule)
# -------------------------
def pycryptodome_aes_bad_external_key_file():
    from Crypto.Cipher import AES
    key = read_key_from_file_bytes("key.bin")     # source
    cipher = AES.new(key, AES.MODE_GCM)           # sink (NO sanitizer) => FLAG
    return cipher


def pycryptodome_aes_bad_external_key_env():
    from Crypto.Cipher import AES
    key = read_key_from_env()                    # source
    cipher = AES.new(key, AES.MODE_CBC, iv=os.urandom(16))  # sink => FLAG
    return cipher


def pycryptodome_aes_bad_external_key_base64():
    from Crypto.Cipher import AES
    key = read_key_from_base64("Zg==")           # source (1-byte after decode)
    cipher = AES.new(key, AES.MODE_ECB)          # sink => FLAG
    return cipher


def cryptography_aes_bad_external_key_hex():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = read_key_from_hex("0011")              # source (2 bytes)
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv))  # sink => FLAG
    return c


# -------------------------
# C) External key + explicit validation (should NOT be flagged by taint rule)
# -------------------------
def pycryptodome_aes_good_external_key_with_check():
    from Crypto.Cipher import AES
    key = read_key_from_file_bytes("key.bin")     # source

    if len(key) not in (16, 24, 32):              # sanitizer
        raise ValueError("invalid AES key length")

    cipher = AES.new(key, AES.MODE_GCM)           # sink (sanitized) => OK
    return cipher


def cryptography_aes_good_external_key_with_assert():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = read_key_from_env()                     # source
    key = key[:32] if len(key) >= 32 else key     # (may or may not be allowed by your policy)
    assert len(key) in (16, 24, 32)               # sanitizer
    iv = os.urandom(16)

    c = Cipher(algorithms.AES(key), modes.CBC(iv))  # sink => OK
    return c


# -------------------------
# D) Optional normalization via slicing (only "good" if your sanitizers allow slicing)
# -------------------------
def pycryptodome_aes_normalize_by_slicing():
    from Crypto.Cipher import AES
    key = read_key_from_file_bytes("key.bin")  # source

    key32 = key[:32]                            # sanitizer (policy-dependent)
    cipher = AES.new(key32, AES.MODE_GCM)       # sink => OK if slicing is allowed
    return cipher


# -------------------------
# E) Direct AES uses with known-good literal key sizes (should NOT be flagged)
# -------------------------
def pycryptodome_aes_good_literal_key():
    from Crypto.Cipher import AES
    key = b"0123456789abcdef"      # 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher


def cryptography_aes_good_literal_key():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    return c


# -------------------------
# F) KDF length parameter checks (explicit length should be flagged if not 16/24/32)
# -------------------------
def cryptography_kdf_bad_length():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(algorithm=hashes.SHA256(), length=20, salt=None, info=b"ctx")  # BAD length => FLAG
    key = hkdf.derive(b"ikm")
    return key


def cryptography_kdf_good_length():
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ctx")  # GOOD
    key = hkdf.derive(b"ikm")
    return key

# -------------------------
# SP 800-56A Concat KDF (Hash)
# -------------------------
def sp80056a_concatkdfhash_good_32():
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # GOOD: 32 bytes (AES-256)
    kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"context")
    key = kdf.derive(b"shared_secret_material")
    return key


def sp80056a_concatkdfhash_bad_20():
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # BAD: 20 bytes (not 16/24/32)
    kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=20, otherinfo=b"context")
    key = kdf.derive(b"shared_secret_material")
    return key


# -------------------------
# SP 800-56A Concat KDF (HMAC)
# -------------------------
def sp80056a_concatkdfhmac_good_16():
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # GOOD: 16 bytes (AES-128)
    kdf = ConcatKDFHMAC(algorithm=hashes.SHA256(), length=16, otherinfo=b"context", salt=None)
    key = kdf.derive(b"shared_secret_material")
    return key


def sp80056a_concatkdfhmac_bad_33():
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHMAC  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # BAD: 33 bytes (not 16/24/32)
    kdf = ConcatKDFHMAC(algorithm=hashes.SHA256(), length=33, otherinfo=b"context", salt=None)
    key = kdf.derive(b"shared_secret_material")
    return key


# -------------------------
# ANSI X9.63 KDF (X963KDF)
# -------------------------
def x963kdf_good_24():
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # GOOD: 24 bytes (AES-192)
    kdf = X963KDF(algorithm=hashes.SHA256(), length=24, sharedinfo=b"context")
    key = kdf.derive(b"shared_secret_material")
    return key


def x963kdf_bad_31():
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore

    # BAD: 31 bytes (not 16/24/32)
    kdf = X963KDF(algorithm=hashes.SHA256(), length=31, sharedinfo=b"context")
    key = kdf.derive(b"shared_secret_material")
    return key


if __name__ == "__main__":
    # This is a Semgrep test corpus. It does not need to run successfully.
    print("AES key-length Semgrep test corpus loaded.")
