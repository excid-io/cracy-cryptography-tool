# configs/symmetric-constructions/tests/disk_encryption_schemes.py

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _sector_number_to_16_bytes(sector_number: int) -> bytes:
    """
    Convert a sector number into a 16-byte little-endian value.
    This is suitable as:
    - an XTS tweak
    - input to ESSIV IV derivation
    """
    return sector_number.to_bytes(16, byteorder="little", signed=False)


def _derive_essiv_iv(key: bytes, sector_number: int) -> bytes:
    """
    Derive an ESSIV IV:
      IV = AES-ECB(hash(key), sector_number)

    This is a simplified CBC-ESSIV construction for testing purposes.

    For AES-128 CBC, we derive a 128-bit ESSIV key by hashing the key with SHA-256
    and truncating to 16 bytes.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    key_hash = digest.finalize()

    essiv_key = key_hash[:16]  # 128-bit AES key for ECB derivation
    sector_block = _sector_number_to_16_bytes(sector_number)

    encryptor = Cipher(algorithms.AES(essiv_key), modes.ECB()).encryptor()
    iv = encryptor.update(sector_block) + encryptor.finalize()
    return iv


def disk_encryption_scheme_examples():
    #
    # Disk-sector-like plaintext.
    # XTS and CBC examples work on block-aligned data.
    #
    sector_plaintext = (
        b"0123456789abcdef"
        b"fedcba9876543210"
        b"AAAABBBBCCCCDDDD"
        b"1111222233334444"
    )  # 64 bytes

    #
    # XTS requires a double-length AES key:
    # - 256 bits total for AES-128-XTS
    # - 512 bits total for AES-256-XTS
    #
    xts_key = (
        b"0123456789abcdef"
        b"fedcba9876543210"
    )  # 32 bytes => AES-128-XTS

    #
    # CBC / CTR use a normal AES key.
    #
    aes_key = b"0123456789abcdef"  # AES-128

    sector_number = 42
    tweak = _sector_number_to_16_bytes(sector_number)

    #
    # ----------------------------------------------------------
    # Agreed disk encryption scheme: XTS
    # Notes:
    # - 10-UniqueTweak
    # - 11-AddressTweak
    # ----------------------------------------------------------
    #
    xts_encryptor = Cipher(algorithms.AES(xts_key), modes.XTS(tweak)).encryptor()
    ciphertext_xts = xts_encryptor.update(sector_plaintext) + xts_encryptor.finalize()

    #
    # ----------------------------------------------------------
    # Legacy disk encryption scheme: CBC-ESSIV
    # Notes:
    # - 12-UniqueSectorNumber
    # - 13-AddressSectorNumber
    # - 14-CBCMalleability
    # ----------------------------------------------------------
    #
    essiv_iv = _derive_essiv_iv(aes_key, sector_number)

    cbc_encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(essiv_iv)).encryptor()
    ciphertext_cbc_essiv = cbc_encryptor.update(sector_plaintext) + cbc_encryptor.finalize()

    #
    # ----------------------------------------------------------
    # Intentionally bad comparison for disk encryption:
    # CTR with sector-derived nonce
    #
    # This is here so you can test Note 9-DiskEncStreamMode.
    # Disk encryption modes are deterministic by nature, and stream modes
    # are improper in that context.
    # ----------------------------------------------------------
    #
    ctr_nonce = tweak
    ctr_encryptor = Cipher(algorithms.AES(aes_key), modes.CTR(ctr_nonce)).encryptor()
    ciphertext_ctr_disk_like = ctr_encryptor.update(sector_plaintext) + ctr_encryptor.finalize()

    return {
        "xts": ciphertext_xts,
        "cbc_essiv": ciphertext_cbc_essiv,
        "ctr_disk_like": ciphertext_ctr_disk_like,
    }