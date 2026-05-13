# configs/integrity-modes/tests/mac_hash_functions.py

from cryptography.hazmat.primitives import hashes, hmac
# PYCA doesn't currently support KMAC, but we want to include test cases for it if/when it is available, so we import it in a way that allows for it to be missing without breaking the whole file.
from cryptography.hazmat.primitives.kmac import KMAC128, KMAC256



def _truncate_tag(tag: bytes, bits: int) -> bytes:
    """
    Truncate a MAC tag to the requested number of bits.

    This helper assumes bits is a multiple of 8 for simplicity.
    It is useful for creating test cases around truncated MAC outputs.
    """
    if bits % 8 != 0:
        raise ValueError("Only whole-byte truncation is supported in this test file.")
    return tag[: bits // 8]


def mac_schemes_based_on_hash_functions_examples():
    #
    # Messages used for MAC generation.
    #
    message = b"example message for hash-based mac schemes"

    #
    # ----------------------------------------------------------
    # HMAC with SHA-256
    #
    # ECCG table:
    # - agreed when key size >= 125 bits
    # - legacy when key size >= 100 bits
    # - non recommended when key size < 100 bits
    # - Note 19-QuantumThreat
    #
    # We include two keys to model both cases.
    # ----------------------------------------------------------
    #
    hmac_sha256_key_agreed = b"0123456789abcdef"  # 16 bytes = 128 bits
    hmac_sha256_ctx_agreed = hmac.HMAC(hmac_sha256_key_agreed, hashes.SHA256())
    hmac_sha256_ctx_agreed.update(message)
    hmac_sha256_tag_agreed_full = hmac_sha256_ctx_agreed.finalize()

    hmac_sha256_key_legacy = b"abcdefghijklm"  # 13 bytes = 104 bits
    hmac_sha256_ctx_legacy = hmac.HMAC(hmac_sha256_key_legacy, hashes.SHA256())
    hmac_sha256_ctx_legacy.update(message)
    hmac_sha256_tag_legacy_full = hmac_sha256_ctx_legacy.finalize()

    #
    # Truncation examples for HMAC-SHA-256.
    #
    hmac_sha256_tag_agreed_96 = _truncate_tag(hmac_sha256_tag_agreed_full, 96)
    hmac_sha256_tag_legacy_64 = _truncate_tag(hmac_sha256_tag_legacy_full, 64)

    #
    # ----------------------------------------------------------
    # HMAC-SHA-1
    #
    # ECCG table:
    # - legacy if key size >= 100 bits
    # - Note 18-HMAC-SHA-1
    # - Note 19-QuantumThreat
    #
    # This is included specifically so CBOMkit can detect HMAC + SHA-1 use.
    # ----------------------------------------------------------
    #
    hmac_sha1_key_legacy = b"abcdefghijklm"  # 13 bytes = 104 bits
    hmac_sha1_ctx_legacy = hmac.HMAC(hmac_sha1_key_legacy, hashes.SHA1())
    hmac_sha1_ctx_legacy.update(message)
    hmac_sha1_tag_legacy_full = hmac_sha1_ctx_legacy.finalize()

    hmac_sha1_tag_legacy_96 = _truncate_tag(hmac_sha1_tag_legacy_full, 96)

    #
    # ----------------------------------------------------------
    # HMAC with an intentionally too-short key
    #
    # This gives us a test case for "below ECCG legacy threshold".
    # ----------------------------------------------------------
    #
    hmac_sha256_key_too_short = b"shortkey1234"  # 12 bytes = 96 bits
    hmac_sha256_ctx_too_short = hmac.HMAC(hmac_sha256_key_too_short, hashes.SHA256())
    hmac_sha256_ctx_too_short.update(message)
    hmac_sha256_tag_too_short_full = hmac_sha256_ctx_too_short.finalize()

    #
    # ----------------------------------------------------------
    # KMAC128 / KMAC256
    #
    # ECCG table:
    # - KMAC128 agreed when key size >= 125 bits
    # - KMAC256 agreed when key size >= 250 bits
    #
    # ----------------------------------------------------------
    #
    kmac128_tag_full = None
    kmac256_tag_full = None
    kmac128_tag_96 = None
    kmac256_tag_96 = None

    kmac128_key_agreed = b"0123456789abcdef"  # 128 bits
    kmac128_ctx = KMAC128(kmac128_key_agreed, 32, b"")
    kmac128_ctx.update(message)
    kmac128_tag_full = kmac128_ctx.finalize()
    kmac128_tag_96 = _truncate_tag(kmac128_tag_full, 96)

    kmac256_key_agreed = (
        b"0123456789abcdef"
        b"fedcba9876543210"
    )  # 32 bytes = 256 bits
    kmac256_ctx = KMAC256(kmac256_key_agreed, 32, b"")
    kmac256_ctx.update(message)
    kmac256_tag_full = kmac256_ctx.finalize()
    kmac256_tag_96 = _truncate_tag(kmac256_tag_full, 96)

    return {
        #
        # HMAC-SHA-256, agreed key length
        #
        "hmac_sha256_agreed_full": hmac_sha256_tag_agreed_full,
        "hmac_sha256_agreed_96": hmac_sha256_tag_agreed_96,
        #
        # HMAC-SHA-256, legacy key length
        #
        "hmac_sha256_legacy_full": hmac_sha256_tag_legacy_full,
        "hmac_sha256_legacy_64": hmac_sha256_tag_legacy_64,
        #
        # HMAC-SHA-1, legacy
        #
        "hmac_sha1_legacy_full": hmac_sha1_tag_legacy_full,
        "hmac_sha1_legacy_96": hmac_sha1_tag_legacy_96,
        #
        # HMAC-SHA-256, too-short key
        #
        "hmac_sha256_too_short_full": hmac_sha256_tag_too_short_full,
        #
        # KMAC, if supported by the installed cryptography version
        #
        "kmac128_full": kmac128_tag_full,
        "kmac128_96": kmac128_tag_96,
        "kmac256_full": kmac256_tag_full,
        "kmac256_96": kmac256_tag_96,
    }