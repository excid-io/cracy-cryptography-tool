# configs/symmetric-constructions/tests/mac_universal_hash.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _truncate_tag(tag: bytes, bits: int) -> bytes:
    """
    Truncate a tag to the requested number of bits.

    This is included so policy/CBOM testing can observe a manually
    truncated GMAC-style tag, even though AESGCM itself emits 128-bit tags.
    """
    if bits % 8 != 0:
        raise ValueError("Only whole-byte truncation supported.")
    return tag[: bits // 8]


def _gmac_like_tag(aesgcm: AESGCM, nonce: bytes, aad: bytes) -> bytes:
    """
    Compute a GMAC-like tag using AESGCM.

    GMAC is essentially GCM used for authentication only:
      - plaintext = empty
      - authenticated data = input to authenticate

    With AESGCM.encrypt(), if plaintext is empty, the returned value
    consists only of the 128-bit authentication tag.
    """
    return aesgcm.encrypt(nonce, b"", aad)


def gmac_examples():
    #
    # AES-128 key
    #
    aes_key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(aes_key)

    #
    # Data to authenticate only
    #
    aad_message = b"example authenticated metadata"

    #
    # ----------------------------------------------------------
    # Agreed-style GMAC-like example
    #
    # Note 22-GMAC-GCMNonce:
    # nonce uniqueness matters
    #
    # Note 23-GMAC-GCMOptions:
    # 96-bit nonce and 128-bit MAC length are the agreed options
    # ----------------------------------------------------------
    #
    nonce_96 = b"unique_nonce"  # 12 bytes = 96 bits
    gmac_tag_128 = _gmac_like_tag(aesgcm, nonce_96, aad_message)

    #
    # ----------------------------------------------------------
    # Intentionally non-agreed example:
    # manual truncation to 96 bits
    #
    # Note 25-GMAC-GCM-Bounds says agreed GMAC/GCM options require
    # a 128-bit MAC length.
    #
    # AESGCM itself still produces a 128-bit tag; we truncate manually
    # afterwards so the codebase contains a truncation example.
    # ----------------------------------------------------------
    #
    gmac_tag_96 = _truncate_tag(gmac_tag_128, 96)

    #
    # ----------------------------------------------------------
    # Intentionally questionable ECCG-policy example:
    # non-96-bit nonce
    #
    # AESGCM can still be called this way, but ECCG only agrees with
    # 96-bit IV/nonce usage in this context.
    # ----------------------------------------------------------
    #
    nonce_non_96 = b"bad_nonce_length"  # 16 bytes
    gmac_tag_non_96_nonce = _gmac_like_tag(aesgcm, nonce_non_96, aad_message)

    return {
        "gmac_128": gmac_tag_128,
        "gmac_96": gmac_tag_96,
        "gmac_non_96_nonce": gmac_tag_non_96_nonce,
    }