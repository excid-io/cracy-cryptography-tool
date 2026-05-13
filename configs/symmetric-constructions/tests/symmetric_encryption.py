# configs/symmetric-constructions/tests/symmetric_encryption_schemes.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


def symmetric_encryption_scheme_examples():
    key = b"0123456789abcdef"                # AES-128
    constant_iv = b"1234567890abcdef"        # deliberately fixed/predictable IV
    nonce = b"1234567890123456"              # 16 bytes for CTR/OFB/CFB examples
    gcm_nonce = b"123456789012"              # 12-byte nonce for GCM
    plaintext = b"hello world!!!!!"          # 16 bytes
    short_plaintext = b"needs padding"       # not block aligned

    #
    # Agreed symmetric encryption schemes from the table
    #

    # AES-CTR (R* / Note 7: stream mode)
    encryptor_ctr = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    ciphertext_ctr = encryptor_ctr.update(plaintext) + encryptor_ctr.finalize()

    # AES-OFB (R* / Note 7: stream mode)
    encryptor_ofb = Cipher(algorithms.AES(key), modes.OFB(nonce)).encryptor()
    ciphertext_ofb = encryptor_ofb.update(plaintext) + encryptor_ofb.finalize()

    # AES-CFB (R* / Note 8: padding-related family in notes)
    encryptor_cfb = Cipher(algorithms.AES(key), modes.CFB(nonce)).encryptor()
    ciphertext_cfb = encryptor_cfb.update(plaintext) + encryptor_cfb.finalize()

    #
    # CBC examples for Note 5 and Note 8
    #

    # AES-CBC with a constant/predictable IV
    # This is intentionally here so policy can flag the IV warning.
    encryptor_cbc_constant_iv = Cipher(algorithms.AES(key), modes.CBC(constant_iv)).encryptor()
    ciphertext_cbc_constant_iv = encryptor_cbc_constant_iv.update(plaintext) + encryptor_cbc_constant_iv.finalize()

    # AES-CBC with PKCS7 padding
    # This is here so the policy/report can associate CBC with padding concerns.
    padder = padding.PKCS7(128).padder()
    padded_short_plaintext = padder.update(short_plaintext) + padder.finalize()

    encryptor_cbc_padded = Cipher(algorithms.AES(key), modes.CBC(constant_iv)).encryptor()
    ciphertext_cbc_padded = encryptor_cbc_padded.update(padded_short_plaintext) + encryptor_cbc_padded.finalize()

    #
    # Non-agreed / comparison modes
    #

    # AES-ECB
    # This should be flagged as not in the agreed scheme list.
    encryptor_ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ciphertext_ecb = encryptor_ecb.update(plaintext) + encryptor_ecb.finalize()

    # AES-GCM
    # Useful comparison point: authenticated encryption mode.
    encryptor_gcm = Cipher(algorithms.AES(key), modes.GCM(gcm_nonce)).encryptor()
    ciphertext_gcm = encryptor_gcm.update(plaintext) + encryptor_gcm.finalize()

    return {
        "ctr": ciphertext_ctr,
        "ofb": ciphertext_ofb,
        "cfb": ciphertext_cfb,
        "cbc_constant_iv": ciphertext_cbc_constant_iv,
        "cbc_padded": ciphertext_cbc_padded,
        "ecb": ciphertext_ecb,
        "gcm": ciphertext_gcm,
    }