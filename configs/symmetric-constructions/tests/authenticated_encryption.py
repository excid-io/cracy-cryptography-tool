# configs/symmetric-constructions/tests/authenticated_encryption.py

from cryptography.hazmat.primitives import hashes, padding, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives.hmac import HMAC


def encrypt_then_mac_example():
    """
    Agreed scheme: Encrypt-then-MAC

    Encrypt with AES-CBC, then authenticate the ciphertext with HMAC-SHA256.
    """
    enc_key = b"0123456789abcdef"                  # AES-128
    mac_key = b"abcdef0123456789abcdef0123456789"  # 32 bytes
    iv = b"1234567890abcdef"
    plaintext = b"authenticated encryption example"
    aad = b"header"

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    mac = HMAC(mac_key, hashes.SHA256())
    mac.update(aad)
    mac.update(iv)
    mac.update(ciphertext)
    tag = mac.finalize()

    return {
        "scheme": "encrypt_then_mac",
        "iv": iv,
        "aad": aad,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def aes_ccm_example():
    """
    Agreed scheme: CCM
    """
    key = b"0123456789abcdef"   # AES-128
    nonce = b"12345678901"      # 11 bytes, valid for CCM
    plaintext = b"ccm message"
    aad = b"header"

    aesccm = aead.AESCCM(key, tag_length=16)
    ciphertext = aesccm.encrypt(nonce, plaintext, aad)

    return {
        "scheme": "ccm",
        "nonce": nonce,
        "aad": aad,
        "ciphertext": ciphertext,
    }


def aes_gcm_example():
    """
    Agreed scheme: GCM

    Uses 96-bit IV and 128-bit tag to align with the note requirements.
    """
    key = b"0123456789abcdef"   # AES-128
    iv = b"123456789012"        # 12 bytes = 96 bits
    plaintext = b"gcm message"
    aad = b"header"

    aesgcm = aead.AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, aad)

    return {
        "scheme": "gcm",
        "iv": iv,
        "aad": aad,
        "ciphertext": ciphertext,
    }


def mac_then_encrypt_example():
    """
    Legacy scheme: MAC-then-Encrypt

    Compute MAC over plaintext first, append it to the plaintext,
    then encrypt the combined value using AES-CBC.
    """
    enc_key = b"0123456789abcdef"
    mac_key = b"abcdef0123456789abcdef0123456789"
    iv = b"1234567890abcdef"
    plaintext = b"legacy mac-then-encrypt"
    aad = b"header"

    mac = HMAC(mac_key, hashes.SHA256())
    mac.update(aad)
    mac.update(plaintext)
    tag = mac.finalize()

    combined = plaintext + tag

    padder = padding.PKCS7(128).padder()
    padded_combined = padder.update(combined) + padder.finalize()

    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_combined) + encryptor.finalize()

    return {
        "scheme": "mac_then_encrypt",
        "iv": iv,
        "aad": aad,
        "ciphertext": ciphertext,
    }


def encrypt_and_mac_example():
    """
    Legacy scheme: Encrypt-and-MAC

    Encrypt plaintext and independently MAC the plaintext.
    """
    enc_key = b"0123456789abcdef"
    mac_key = b"abcdef0123456789abcdef0123456789"
    iv = b"1234567890abcdef"
    plaintext = b"legacy encrypt-and-mac"
    aad = b"header"

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    mac = HMAC(mac_key, hashes.SHA256())
    mac.update(aad)
    mac.update(plaintext)
    tag = mac.finalize()

    return {
        "scheme": "encrypt_and_mac",
        "iv": iv,
        "aad": aad,
        "ciphertext": ciphertext,
        "tag": tag,
    }


def all_authenticated_encryption_examples():
    return {
        "encrypt_then_mac": encrypt_then_mac_example(),
        "ccm": aes_ccm_example(),
        "gcm": aes_gcm_example(),
        "mac_then_encrypt": mac_then_encrypt_example(),
        "encrypt_and_mac": encrypt_and_mac_example(),
    }