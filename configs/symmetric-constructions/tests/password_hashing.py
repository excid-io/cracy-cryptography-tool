# configs/symmetric-constructions/tests/password_hashing.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def pbkdf2_recommended_example():
    """
    PBKDF2 with:
    - SHA-256
    - 128-bit salt (16 bytes)
    - relatively strong iteration count
    """
    password = b"correct horse battery staple"
    salt = b"0123456789abcdef"  # 16 bytes = 128 bits
    iterations = 600_000
    length = 32

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password)

    return {
        "scheme": "pbkdf2",
        "salt": salt,
        "iterations": iterations,
        "derived_key": derived_key,
    }


def pbkdf2_short_salt_example():
    """
    PBKDF2 with a salt shorter than 128 bits.
    Should be flagged for Note 28-Salt.
    """
    password = b"correct horse battery staple"
    salt = b"shortsalt"  # 9 bytes = 72 bits
    iterations = 600_000
    length = 32

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password)

    return {
        "scheme": "pbkdf2",
        "salt": salt,
        "iterations": iterations,
        "derived_key": derived_key,
    }


def pbkdf2_low_iterations_example():
    """
    PBKDF2 with an intentionally low iteration count.
    Should be flagged for Note 27-NumberOfIterations.
    """
    password = b"correct horse battery staple"
    salt = b"0123456789abcdef"  # 16 bytes = 128 bits
    iterations = 1_000
    length = 32

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password)

    return {
        "scheme": "pbkdf2",
        "salt": salt,
        "iterations": iterations,
        "derived_key": derived_key,
    }


def pbkdf2_legacy_hash_example():
    """
    PBKDF2 using SHA-1.
    Useful if you also want your hash-policy rules to interact with PBKDF2 usage.
    """
    password = b"correct horse battery staple"
    salt = b"0123456789abcdef"  # 16 bytes = 128 bits
    iterations = 600_000
    length = 32

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password)

    return {
        "scheme": "pbkdf2",
        "salt": salt,
        "iterations": iterations,
        "derived_key": derived_key,
    }


def password_hashing_examples():
    return {
        "pbkdf2_recommended": pbkdf2_recommended_example(),
        "pbkdf2_short_salt": pbkdf2_short_salt_example(),
        "pbkdf2_low_iterations": pbkdf2_low_iterations_example(),
        "pbkdf2_sha1_variant": pbkdf2_legacy_hash_example(),
    }