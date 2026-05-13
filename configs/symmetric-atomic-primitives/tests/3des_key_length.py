# tests/test_3des_keysize.py
import os
import secrets
import base64
import binascii
import ssl
import pathlib
from pathlib import Path

from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes

# These are only needed to type-check the names in the file;
# Semgrep doesn't execute, so missing imports usually don't matter,
# but having them helps readability.
try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
    from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
except Exception:
    HKDF = PBKDF2HMAC = ConcatKDFHash = ConcatKDFHMAC = X963KDF = object


# ==========================================================
# Rule: python.crypto.3des.keysize.bad-explicit-length
# ==========================================================

def test_bad_explicit_os_urandom_16():
    key = os.urandom(16)  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_ok_explicit_os_urandom_24():
    key = os.urandom(24)  # ok: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_bad_explicit_secrets_32():
    key = secrets.token_bytes(32)  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_ok_explicit_secrets_24():
    key = secrets.token_bytes(24)  # ok: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_bad_explicit_pycryptodome_random_8():
    key = get_random_bytes(8)  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_ok_explicit_pycryptodome_random_24():
    key = get_random_bytes(24)  # ok: python.crypto.3des.keysize.bad-explicit-length
    return key

def test_bad_explicit_hkdf_len_16():
    kdf = HKDF(algorithm=None, length=16, salt=None, info=None)  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_ok_explicit_hkdf_len_24():
    kdf = HKDF(algorithm=None, length=24, salt=None, info=None)  # ok: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_bad_explicit_pbkdf2_len_32():
    kdf = PBKDF2HMAC(algorithm=None, length=32, salt=b"salt", iterations=1)  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_ok_explicit_pbkdf2_len_24():
    kdf = PBKDF2HMAC(algorithm=None, length=24, salt=b"salt", iterations=1)  # ok: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_bad_explicit_concatkdfhash_len_20():
    kdf = ConcatKDFHash(algorithm=None, length=20, otherinfo=b"")  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_ok_explicit_concatkdfhash_len_24():
    kdf = ConcatKDFHash(algorithm=None, length=24, otherinfo=b"")  # ok: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_bad_explicit_concatkdfhmac_len_16():
    kdf = ConcatKDFHMAC(algorithm=None, length=16, otherinfo=b"")  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_ok_explicit_concatkdfhmac_len_24():
    kdf = ConcatKDFHMAC(algorithm=None, length=24, otherinfo=b"")  # ok: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_bad_explicit_x963_len_32():
    kdf = X963KDF(algorithm=None, length=32, sharedinfo=b"")  # ruleid: python.crypto.3des.keysize.bad-explicit-length
    return kdf

def test_ok_explicit_x963_len_24():
    kdf = X963KDF(algorithm=None, length=24, sharedinfo=b"")  # ok: python.crypto.3des.keysize.bad-explicit-length
    return kdf


# ==========================================================
# Rule: python.crypto.3des.keysize.unvalidated-external-key (taint)
# ==========================================================

def test_taint_file_read_used_directly():
    key = open("key.bin", "rb").read()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_taint_env_used_directly():
    key = os.getenv("KEY_MATERIAL")
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_taint_decode_used_directly():
    key = base64.b64decode("AAAA")
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_len_assert():
    key = open("key.bin", "rb").read()
    assert len(key) == 24
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_len_guard_raise():
    key = open("key.bin", "rb").read()
    if len(key) != 24:
        raise ValueError("bad key length")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_kdf_derive_24():
    # key comes from KDF( length=24 ).derive(...)
    key = HKDF(algorithm=None, length=24, salt=None, info=None).derive(b"ikm")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_concatkdfhash_derive_24():
    key = ConcatKDFHash(algorithm=None, length=24, otherinfo=b"").derive(b"z")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_x963_derive_24():
    key = X963KDF(algorithm=None, length=24, sharedinfo=b"").derive(b"z")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_ok_with_truncation_if_policy_allows():
    raw = open("key.bin", "rb").read()
    key = raw[:24]
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_taint_pycryptodome_style_fully_qualified():
    key = open("key.bin", "rb").read()
    Crypto.Cipher.DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key  # noqa: F821


# ==========================================================
# Helper-return sources (the exact shapes your patterns match)
# ==========================================================

def helper_return_open_text():
    # matches: return open(...).read()
    return open("key.txt").read()

def helper_return_open_rb():
    # matches: return open(..., "rb").read()
    return open("key.bin", "rb").read()

def helper_return_handle_read():
    # matches: $FH=open(...); return $FH.read()
    fh = open("key.bin", "rb")
    return fh.read()

def helper_return_path_read_bytes():
    # matches: return Path(...).read_bytes()
    return Path("key.bin").read_bytes()

def helper_return_pathlib_read_bytes():
    # matches: return pathlib.Path(...).read_bytes()
    return pathlib.Path("key.bin").read_bytes()

def helper_env_index():
    # matches: os.environ[$K] inside helper
    return os.environ["KEY_MATERIAL"]

def helper_getenv():
    # matches: os.getenv(...) inside helper
    return os.getenv("KEY_MATERIAL")

def helper_return_argv():
    # matches: return sys.argv[$I] inside helper
    return sys.argv[1]

def helper_return_b64decode():
    # matches: return base64.b64decode(...)
    return base64.b64decode("AAAA")

def helper_return_unhexlify():
    # matches: return binascii.unhexlify(...)
    return binascii.unhexlify("00112233445566778899aabbccddeeff0011223344556677")

def helper_return_fromhex():
    # matches: return bytes.fromhex(...)
    return bytes.fromhex("00112233445566778899aabbccddeeff0011223344556677")


# ==========================================================
# Cases that SHOULD be flagged by the taint rule (helpers -> sink)
# python.crypto.3des.keysize.unvalidated-external-key
# ==========================================================

def test_helper_return_open_text_used_as_3des_key():
    key = helper_return_open_text()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_open_rb_used_as_3des_key():
    key = helper_return_open_rb()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_handle_read_used_as_3des_key():
    key = helper_return_handle_read()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_path_read_bytes_used_as_3des_key():
    key = helper_return_path_read_bytes()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_pathlib_read_bytes_used_as_3des_key():
    key = helper_return_pathlib_read_bytes()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_env_index_used_as_3des_key():
    key = helper_env_index()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_getenv_used_as_3des_key():
    key = helper_getenv()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_argv_used_as_3des_key():
    key = helper_return_argv()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_b64decode_used_as_3des_key():
    key = helper_return_b64decode()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_unhexlify_used_as_3des_key():
    key = helper_return_unhexlify()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_return_fromhex_used_as_3des_key():
    key = helper_return_fromhex()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key


# ==========================================================
# Helper cases that SHOULD be OK due to sanitizers
# ==========================================================

def test_helper_then_len_assert_ok():
    key = helper_return_open_rb()
    assert len(key) == 24
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_then_len_guard_raise_ok():
    key = helper_return_open_rb()
    if len(key) != 24:
        raise ValueError("bad key length")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_then_truncate_ok_if_policy_allows():
    raw = helper_return_open_rb()
    key = raw[:24]
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_kdf_derive_24_ok():
    key = HKDF(algorithm=None, length=24, salt=None, info=None).derive(b"ikm")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_concatkdf_derive_24_ok():
    key = ConcatKDFHash(algorithm=None, length=24, otherinfo=b"").derive(b"z")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key

def test_helper_x963_derive_24_ok():
    key = X963KDF(algorithm=None, length=24, sharedinfo=b"").derive(b"z")
    DES3.new(key, DES3.MODE_ECB)  # ok: python.crypto.3des.keysize.unvalidated-external-key


# ==========================================================
# Optional: “function-return source” tests (often Pro-only)
# ==========================================================

def load_key_from_file():
    return open("key.bin", "rb").read()

def test_taint_function_return_source_used():
    key = load_key_from_file()
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.3des.keysize.unvalidated-external-key
