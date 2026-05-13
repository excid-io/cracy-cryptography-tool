# configs/integrity-modes/tests/mac_block_ciphers.py

from cryptography.hazmat.primitives import cmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _truncate_tag(tag: bytes, bits: int) -> bytes:
    """
    Truncate a MAC tag to the requested number of bits.

    The ECCG notes discuss:
    - agreed truncation: at least 96 bits
    - legacy truncation: at least 64 bits under conditions

    This helper assumes bits is a multiple of 8 for simplicity.
    """
    if bits % 8 != 0:
        raise ValueError("Only whole-byte truncation is supported in this test file.")
    return tag[: bits // 8]


def _aes_cbc_mac(key: bytes, message: bytes) -> bytes:
    """
    Compute a basic AES-CBC-MAC over a block-aligned message.

    CBC-MAC is only safe in restricted settings, notably when all messages
    authenticated under the same key have identical length.

    This implementation:
    - uses AES-CBC with a zero IV
    - returns the last ciphertext block as the MAC
    - expects the caller to provide a block-aligned message

    This is intentionally simple so CBOMkit can detect the construction.
    """
    if len(message) % 16 != 0:
        raise ValueError("CBC-MAC test helper expects block-aligned input.")

    zero_iv = b"\x00" * 16
    encryptor = Cipher(algorithms.AES(key), modes.CBC(zero_iv)).encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    return ciphertext[-16:]


def mac_scheme_examples():
    #
    # AES-128 key used for both CMAC and CBC-MAC examples.
    #
    aes_key = b"0123456789abcdef"

    #
    # ----------------------------------------------------------
    # Agreed MAC scheme: CMAC
    # ----------------------------------------------------------
    #
    cmac_message = b"example message for cmac"
    cmac_ctx = cmac.CMAC(algorithms.AES(aes_key))
    cmac_ctx.update(cmac_message)
    cmac_tag_full = cmac_ctx.finalize()

    #
    # Note 15-MACTruncation96:
    # agreed in the general case
    #
    cmac_tag_96 = _truncate_tag(cmac_tag_full, 96)

    #
    # Note 16-MACTruncation64:
    # legacy in the general case, under the bounded-verification condition
    #
    cmac_tag_64 = _truncate_tag(cmac_tag_full, 64)

    #
    # ----------------------------------------------------------
    # Conditionally agreed MAC scheme: CBC-MAC
    #
    # Important note:
    # CBC-MAC is only agreed where all input sizes under the same key
    # are identical. So we deliberately use block-aligned fixed-size inputs.
    # ----------------------------------------------------------
    #
    fixed_length_message_1 = (
        b"BLOCK-0000000001"
        b"BLOCK-0000000002"
    )  # 32 bytes, fixed length

    fixed_length_message_2 = (
        b"BLOCK-0000000003"
        b"BLOCK-0000000004"
    )  # also 32 bytes, same length

    cbc_mac_tag_1_full = _aes_cbc_mac(aes_key, fixed_length_message_1)
    cbc_mac_tag_2_full = _aes_cbc_mac(aes_key, fixed_length_message_2)

    #
    # Truncation examples for CBC-MAC as well.
    #
    cbc_mac_tag_1_96 = _truncate_tag(cbc_mac_tag_1_full, 96)
    cbc_mac_tag_1_64 = _truncate_tag(cbc_mac_tag_1_full, 64)

    #
    # ----------------------------------------------------------
    # Intentionally unsafe CBC-MAC usage example
    #
    # Here we can test the fixed-input-length note.
    # The code computes CBC-MAC on a variable-length message, which is
    # exactly the context the ECCG note warns against.
    #
    # We pad here only so the CBC primitive can run; the security issue is
    # the variable message length under the same key, not whether the code runs.
    # ----------------------------------------------------------
    #
    variable_length_message = b"short message"

    padder = padding.PKCS7(128).padder()
    padded_variable_message = (
        padder.update(variable_length_message) + padder.finalize()
    )

    cbc_mac_variable_length_full = _aes_cbc_mac(aes_key, padded_variable_message)

    return {
        #
        # CMAC
        #
        "cmac_full": cmac_tag_full,
        "cmac_96": cmac_tag_96,
        "cmac_64": cmac_tag_64,
        #
        # CBC-MAC fixed-length examples
        #
        "cbc_mac_fixed_1_full": cbc_mac_tag_1_full,
        "cbc_mac_fixed_2_full": cbc_mac_tag_2_full,
        "cbc_mac_fixed_1_96": cbc_mac_tag_1_96,
        "cbc_mac_fixed_1_64": cbc_mac_tag_1_64,
        #
        # CBC-MAC variable-length example
        #
        "cbc_mac_variable_length_full": cbc_mac_variable_length_full,
    }