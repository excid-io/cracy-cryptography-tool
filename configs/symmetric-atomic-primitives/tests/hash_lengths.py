# tests/test_hash_lengths_policy.py
#
# Semgrep test cases for "hash length policy" ruleset:
# - Legacy (L[2025]) disallowed: SHA-224, SHA-512/224
# - Allowed (R): SHA-256/384/512, SHA-512/256, SHA3-256/384/512
#
# Uses Semgrep annotations:
#   # ruleid: <rule-id>  -> should be flagged
#   # ok: <rule-id>      -> should NOT be flagged

import hashlib
import hmac

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.hmac import HMAC
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
except Exception:
    # Semgrep doesn't execute, but this keeps the file importable if you run it.
    hashes = None
    HMAC = HKDF = PBKDF2HMAC = ConcatKDFHash = ConcatKDFHMAC = X963KDF = object

try:
    from Crypto.Hash import SHA224, SHA256, SHA512, SHA3_256
    # SHA512_224 naming varies across libs; keep a soft import.
    try:
        from Crypto.Hash import SHA512_224
    except Exception:
        SHA512_224 = None
except Exception:
    SHA224 = SHA256 = SHA512 = SHA3_256 = object
    SHA512_224 = None


# ==========================================================
# hashlib tests
# ==========================================================

def test_hashlib_sha224_disallowed():
    hashlib.sha224(b"data").hexdigest()  # ruleid: python.hash.hashlib.sha224.legacy

def test_hashlib_new_sha224_disallowed():
    hashlib.new("sha224", b"data").digest()  # ruleid: python.hash.hashlib.sha224.legacy

def test_hashlib_sha512_224_disallowed():
    hashlib.sha512_224(b"data").hexdigest()  # ruleid: python.hash.hashlib.sha512_224.legacy

def test_hashlib_new_sha512_224_disallowed():
    hashlib.new("sha512_224", b"data").digest()  # ruleid: python.hash.hashlib.sha512_224.legacy

def test_hashlib_sha256_ok():
    hashlib.sha256(b"data").hexdigest()  # ok: python.hash.hashlib.sha224.legacy

def test_hashlib_sha3_256_ok():
    hashlib.sha3_256(b"data").hexdigest()  # ok: python.hash.hashlib.sha224.legacy

def test_hashlib_sha512_256_ok():
    hashlib.sha512_256(b"data").hexdigest()  # ok: python.hash.hashlib.sha512_224.legacy


# ==========================================================
# cryptography hashes tests
# ==========================================================

def test_crypto_sha224_disallowed():
    hashes.SHA224()  # ruleid: python.hash.crypto.sha224.legacy

def test_crypto_sha512_224_disallowed():
    hashes.SHA512_224()  # ruleid: python.hash.crypto.sha512_224.legacy

def test_crypto_sha256_ok():
    hashes.SHA256()  # ok: python.hash.crypto.sha224.legacy

def test_crypto_sha3_256_ok():
    hashes.SHA3_256()  # ok: python.hash.crypto.sha224.legacy

def test_crypto_sha512_256_ok():
    hashes.SHA512_256()  # ok: python.hash.crypto.sha512_224.legacy


# ==========================================================
# HMAC tests
# ==========================================================

def test_stdlib_hmac_sha224_disallowed():
    hmac.new(b"k", b"m", digestmod=hashlib.sha224).digest()  # ruleid: python.hash.hmac.legacy

def test_stdlib_hmac_sha512_224_disallowed():
    hmac.new(b"k", b"m", digestmod=hashlib.sha512_224).digest()  # ruleid: python.hash.hmac.legacy

def test_stdlib_hmac_sha256_ok():
    hmac.new(b"k", b"m", digestmod=hashlib.sha256).digest()  # ok: python.hash.hmac.legacy

def test_crypto_hmac_sha224_disallowed():
    HMAC(b"k"*16, hashes.SHA224())  # ruleid: python.hash.crypto.hmac.legacy

def test_crypto_hmac_sha512_224_disallowed():
    HMAC(b"k"*16, hashes.SHA512_224())  # ruleid: python.hash.crypto.hmac.legacy

def test_crypto_hmac_sha256_ok():
    HMAC(b"k"*16, hashes.SHA256())  # ok: python.hash.crypto.hmac.legacy


# ==========================================================
# KDF tests (cryptography)
# ==========================================================

def test_hkdf_sha224_disallowed():
    HKDF(algorithm=hashes.SHA224(), length=32, salt=None, info=None)  # ruleid: python.hash.crypto.kdf.legacy

def test_hkdf_sha512_224_disallowed():
    HKDF(algorithm=hashes.SHA512_224(), length=32, salt=None, info=None)  # ruleid: python.hash.crypto.kdf.legacy

def test_hkdf_sha256_ok():
    HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=None)  # ok: python.hash.crypto.kdf.legacy

def test_pbkdf2_sha224_disallowed():
    PBKDF2HMAC(algorithm=hashes.SHA224(), length=32, salt=b"s", iterations=1)  # ruleid: python.hash.crypto.kdf.legacy

def test_pbkdf2_sha512_224_disallowed():
    PBKDF2HMAC(algorithm=hashes.SHA512_224(), length=32, salt=b"s", iterations=1)  # ruleid: python.hash.crypto.kdf.legacy

def test_pbkdf2_sha256_ok():
    PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"s", iterations=1)  # ok: python.hash.crypto.kdf.legacy

def test_concatkdfhash_sha224_disallowed():
    ConcatKDFHash(algorithm=hashes.SHA224(), length=32, otherinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_concatkdfhash_sha512_224_disallowed():
    ConcatKDFHash(algorithm=hashes.SHA512_224(), length=32, otherinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_concatkdfhash_sha256_ok():
    ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=b"")  # ok: python.hash.crypto.kdf.legacy

def test_concatkdfhmac_sha224_disallowed():
    ConcatKDFHMAC(algorithm=hashes.SHA224(), length=32, otherinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_concatkdfhmac_sha512_224_disallowed():
    ConcatKDFHMAC(algorithm=hashes.SHA512_224(), length=32, otherinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_concatkdfhmac_sha256_ok():
    ConcatKDFHMAC(algorithm=hashes.SHA256(), length=32, otherinfo=b"")  # ok: python.hash.crypto.kdf.legacy

def test_x963kdf_sha224_disallowed():
    X963KDF(algorithm=hashes.SHA224(), length=32, sharedinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_x963kdf_sha512_224_disallowed():
    X963KDF(algorithm=hashes.SHA512_224(), length=32, sharedinfo=b"")  # ruleid: python.hash.crypto.kdf.legacy

def test_x963kdf_sha256_ok():
    X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=b"")  # ok: python.hash.crypto.kdf.legacy


# ==========================================================
# PyCryptodome tests
# ==========================================================

def test_pycryptodome_sha224_disallowed():
    SHA224.new(data=b"data").digest()  # ruleid: python.hash.pycryptodome.legacy

def test_pycryptodome_sha256_ok():
    SHA256.new(data=b"data").digest()  # ok: python.hash.pycryptodome.legacy

def test_pycryptodome_sha512_224_disallowed_if_available():
    # If SHA512_224 exists, this should be flagged.
    # Semgrep scans the syntax; the symbol doesn't need to exist at runtime.
    if SHA512_224 is not None:
        SHA512_224.new(data=b"data").digest()  # ruleid: python.hash.pycryptodome.legacy

def test_pycryptodome_sha3_256_ok():
    SHA3_256.new(data=b"data").digest()  # ok: python.hash.pycryptodome.legacy
