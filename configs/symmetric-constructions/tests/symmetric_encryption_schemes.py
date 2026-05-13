# tests/test_symmetric_modes_eccg_policy.py
#
# Semgrep test cases for:
# - python.crypto.symm.mode.confidentiality_only_requires_integrity (WARNING)
# - python.crypto.symm.iv_or_nonce.fixed_or_predictable (ERROR)
# - python.crypto.symm.aes.non_aead_mode (WARNING)
# - python.crypto.symm.eccg.non_recommended_mode (ERROR)
#
# Uses Semgrep annotations:
#   # ruleid: <rule-id> -> should be flagged
#   # ok: <rule-id>     -> should NOT be flagged

import os
import ssl

# cryptography imports (not executed by Semgrep; try/except keeps runtime optional)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except Exception:
    Cipher = algorithms = modes = object  # type: ignore

# PyCryptodome / PyCrypto imports (not executed by Semgrep; try/except keeps runtime optional)
try:
    from Crypto.Cipher import AES, DES3
except Exception:
    AES = DES3 = object  # type: ignore


# ==========================================================
# 1) ECCG R* modes: CTR/OFB/CBC/CFB (should WARN)
# ==========================================================

def test_crypto_modes_cbc_warn():
    iv = os.urandom(16)
    m = modes.CBC(iv)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    return m

def test_crypto_modes_ctr_warn():
    nonce = os.urandom(16)
    m = modes.CTR(nonce)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    return m

def test_crypto_modes_ofb_warn():
    iv = os.urandom(16)
    m = modes.OFB(iv)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    return m

def test_crypto_modes_cfb_warn():
    iv = os.urandom(16)
    m = modes.CFB(iv)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    return m

def test_pycryptodome_aes_cbc_warn():
    key = os.urandom(16)
    iv = os.urandom(16)
    AES.new(key, AES.MODE_CBC, iv=iv)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    AES.new(key, AES.MODE_CBC, iv=iv)  # ruleid: python.crypto.symm.aes.non_aead_mode

def test_pycryptodome_aes_ctr_warn():
    key = os.urandom(16)
    AES.new(key, AES.MODE_CTR)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
    AES.new(key, AES.MODE_CTR)  # ruleid: python.crypto.symm.aes.non_aead_mode

def test_pycryptodome_des3_cfb_warn():
    key = os.urandom(24)
    iv = os.urandom(8)
    DES3.new(key, DES3.MODE_CFB, iv=iv)  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity


# ==========================================================
# 2) Fixed/predictable IV/nonce (should ERROR)
# ==========================================================

def test_crypto_fixed_literal_iv_error():
    m = modes.CBC(b"\x00" * 16)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable
    return m

def test_crypto_bytes_constant_iv_error():
    m = modes.CFB(bytes(16))  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable
    return m

def test_crypto_bytearray_constant_iv_error():
    m = modes.OFB(bytearray(16))  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable
    return m

def test_crypto_fixed_literal_nonce_error():
    m = modes.CTR(b"\x01" * 16)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable
    return m

def test_pycryptodome_fixed_iv_literal_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_CBC, iv=b"\x00" * 16)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable

def test_pycryptodome_fixed_nonce_literal_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_CTR, nonce=b"\x00" * 8)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable

def test_pycryptodome_ctr_initial_value_zero_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_CTR, initial_value=0)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable

def test_des3_fixed_iv_literal_error():
    key = os.urandom(24)
    DES3.new(key, DES3.MODE_CBC, iv=b"\x00" * 8)  # ruleid: python.crypto.symm.iv_or_nonce.fixed_or_predictable


# ==========================================================
# 3) Non-ECCG modes (NOT RECOMMENDED) (should ERROR)
#    Examples: ECB, GCM, CCM, EAX, SIV, OCB, XTS, etc.
# ==========================================================

def test_crypto_mode_ecb_nonrecommended_error():
    # cryptography mode not in allowlist
    m = modes.ECB()  # ruleid: python.crypto.symm.eccg.non_recommended_mode
    return m

def test_crypto_mode_gcm_nonrecommended_error():
    # Even though AEAD is good, your current allowlist flags it as "not ECCG recommended"
    m = modes.GCM(os.urandom(12))  # ruleid: python.crypto.symm.eccg.non_recommended_mode
    return m

def test_crypto_mode_xts_nonrecommended_error():
    m = modes.XTS(os.urandom(16))  # ruleid: python.crypto.symm.eccg.non_recommended_mode
    return m

def test_pycryptodome_aes_ecb_nonrecommended_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_ECB)  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_pycryptodome_aes_gcm_nonrecommended_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_pycryptodome_aes_ccm_nonrecommended_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_CCM, nonce=os.urandom(11))  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_pycryptodome_aes_eax_nonrecommended_error():
    key = os.urandom(16)
    AES.new(key, AES.MODE_EAX, nonce=os.urandom(16))  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_pycryptodome_aes_siv_nonrecommended_error():
    key = os.urandom(32)
    AES.new(key, AES.MODE_SIV, nonce=os.urandom(16))  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_pycryptodome_des3_ecb_nonrecommended_error():
    key = os.urandom(24)
    DES3.new(key, DES3.MODE_ECB)  # ruleid: python.crypto.symm.eccg.non_recommended_mode


# ==========================================================
# 4) "OK" examples (should not match specific rules)
#    NOTE: With the allowlist, AEAD modes are NOT OK (they'll be flagged).
#    So "ok" here means "does not trigger the fixed IV rule", or
#    "does not trigger AES non-AEAD rule", etc.
# ==========================================================

def test_crypto_cbc_random_iv_ok_for_fixed_iv_rule():
    # Should still WARN for confidentiality-only mode, but should NOT ERROR for fixed IV
    iv = os.urandom(16)
    m = modes.CBC(iv)  # ok: python.crypto.symm.iv_or_nonce.fixed_or_predictable
    return m

def test_pycryptodome_cbc_random_iv_ok_for_fixed_iv_rule():
    key = os.urandom(16)
    iv = os.urandom(16)
    AES.new(key, AES.MODE_CBC, iv=iv)  # ok: python.crypto.symm.iv_or_nonce.fixed_or_predictable

def test_ssl_set_ciphers_non_eccg_heuristic_error():
    # This triggers the heuristic cipher-string detector (GCM)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")  # ruleid: python.crypto.symm.eccg.non_recommended_mode

def test_ssl_set_ciphers_cbc_cs_warn():
    # Best-effort CBC-CS detection (rare in practice)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("CBC-CS")  # ruleid: python.crypto.symm.mode.confidentiality_only_requires_integrity
