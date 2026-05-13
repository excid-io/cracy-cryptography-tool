# configs/symmetric-constructions/tests/key_protection.py

from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap,
    aes_key_wrap_with_padding,
    aes_key_unwrap_with_padding,
)


def aes_siv_key_protection_example():
    """
    Agreed scheme: SIV [RFC5297]

    Demonstrates deterministic misuse-resistant authenticated encryption
    suitable for protecting key material together with associated metadata.
    """

    # AESSIV requires a doubled-length AES key:
    # 32 bytes for AES-128-SIV, 48 for AES-192-SIV, 64 for AES-256-SIV.
    siv_key = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    key_to_protect = b"fedcba9876543210"  # 16-byte wrapped key material

    # Associated data can bind context such as key id, algorithm, tenant, etc.
    aad = [
        b"purpose:key-protection",
        b"algorithm:AES-128",
        b"key-id:demo-key-1",
    ]

    aessiv = AESSIV(siv_key)

    protected = aessiv.encrypt(key_to_protect, aad)
    recovered = aessiv.decrypt(protected, aad)

    assert recovered == key_to_protect

    return {
        "scheme": "siv",
        "aad": aad,
        "protected_key": protected,
        "recovered_key": recovered,
    }


def aes_key_wrap_example():
    """
    Agreed scheme: AES-Keywrap [SP800-38F, KW]

    Demonstrates NIST AES key wrap for key transport/storage when the
    key material length is a multiple of 64 bits.
    """

    kek = b"000102030405060708090a0b0c0d0e0f"  # 16-byte KEK
    key_to_wrap = b"00112233445566778899aabbccddeeff"  # 16 bytes

    wrapped = aes_key_wrap(kek, key_to_wrap)
    unwrapped = aes_key_unwrap(kek, wrapped)

    assert unwrapped == key_to_wrap

    return {
        "scheme": "aes-keywrap-kw",
        "kek": kek,
        "wrapped_key": wrapped,
        "unwrapped_key": unwrapped,
    }


def aes_key_wrap_with_padding_example():
    """
    Agreed scheme: AES-Keywrap [SP800-38F, KWP]

    Demonstrates padded AES key wrap for key material whose length is not
    necessarily a multiple of 64 bits.
    """

    kek = b"000102030405060708090a0b0c0d0e0f"  # 16-byte KEK
    key_to_wrap = b"short-demo-key-123"  # 18 bytes, not 8-byte aligned

    wrapped = aes_key_wrap_with_padding(kek, key_to_wrap)
    unwrapped = aes_key_unwrap_with_padding(kek, wrapped)

    assert unwrapped == key_to_wrap

    return {
        "scheme": "aes-keywrap-kwp",
        "kek": kek,
        "wrapped_key": wrapped,
        "unwrapped_key": unwrapped,
    }


def all_key_protection_examples():
    return {
        "siv": aes_siv_key_protection_example(),
        "aes_key_wrap_kw": aes_key_wrap_example(),
        "aes_key_wrap_kwp": aes_key_wrap_with_padding_example(),
    }


if __name__ == "__main__":
    examples = all_key_protection_examples()
    for name, result in examples.items():
        print(f"{name}: ok, produced {len(result['wrapped_key'] if 'wrapped_key' in result else result['protected_key'])} bytes")