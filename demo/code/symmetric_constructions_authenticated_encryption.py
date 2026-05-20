from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_KEY = b"A" * 16      # AES-128
HMAC_KEY = b"H" * 32     # HMAC key
IV = b"I" * 16           # CBC IV, fixed here only for deterministic test code


def pkcs7_pad(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def hmac_sha256(data: bytes) -> bytes:
    mac = hmac.HMAC(HMAC_KEY, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def aes_cbc_encrypt(data: bytes) -> bytes:
    cipher = Cipher(
        algorithms.AES(AES_KEY),
        modes.CBC(IV),
    )

    encryptor = cipher.encryptor()
    padded = pkcs7_pad(data)

    return encryptor.update(padded) + encryptor.finalize()


def fire_legacy_mac_then_encrypt():
    """
    Legacy AE scheme: MAC-then-Encrypt.

    Construction:
      1. Compute MAC over plaintext.
      2. Append MAC to plaintext.
      3. Encrypt plaintext || MAC.

    This corresponds to:
      MAC-then-Encrypt [BN00] L[2025]
    """

    plaintext = b"message protected with MAC-then-Encrypt"

    tag = hmac_sha256(plaintext)
    plaintext_and_tag = plaintext + tag

    ciphertext = aes_cbc_encrypt(plaintext_and_tag)

    return ciphertext


def fire_legacy_encrypt_and_mac():
    """
    Legacy AE scheme: Encrypt-and-MAC.

    Construction:
      1. Encrypt plaintext.
      2. Compute MAC over plaintext separately.
      3. Output ciphertext and tag.

    This corresponds to:
      Encrypt-and-MAC [BN00] L[2025]
    """

    plaintext = b"message protected with Encrypt-and-MAC"

    ciphertext = aes_cbc_encrypt(plaintext)
    tag = hmac_sha256(plaintext)

    return ciphertext, tag


if __name__ == "__main__":
    mac_then_encrypt_ct = fire_legacy_mac_then_encrypt()
    encrypt_and_mac_ct, encrypt_and_mac_tag = fire_legacy_encrypt_and_mac()

    print("MAC-then-Encrypt ciphertext:", mac_then_encrypt_ct.hex())
    print("Encrypt-and-MAC ciphertext:", encrypt_and_mac_ct.hex())
    print("Encrypt-and-MAC tag:", encrypt_and_mac_tag.hex())