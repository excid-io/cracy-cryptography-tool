from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def fire_eccg_block_001_blowfish():
    """
    Fires ECCG-BLOCK-001:
    Blowfish is a block cipher, but it is not AES or 3DES.
    """

    key = b"K" * 16      # Blowfish key
    iv = b"I" * 8        # Blowfish has a 64-bit block size

    cipher = Cipher(
        algorithms.Blowfish(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()
    plaintext = b"A" * 16

    return encryptor.update(plaintext) + encryptor.finalize()


def fire_eccg_block_003_and_004_triple_des():
    """
    Fires ECCG-BLOCK-003 and ECCG-BLOCK-004:
    TripleDES is a 3DES component.

    ECCG-BLOCK-003 should fire if CBOMkit records the detected
    parameter/key size as something other than 168.

    ECCG-BLOCK-004 fires for any 3DES component.
    """

    key = b"1234567890ABCDEF"  # 16-byte / two-key TripleDES material
    iv = b"12345678"           # 3DES has a 64-bit block size

    cipher = Cipher(
        algorithms.TripleDES(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()
    plaintext = b"B" * 16

    return encryptor.update(plaintext) + encryptor.finalize()


if __name__ == "__main__":
    blowfish_ciphertext = fire_eccg_block_001_blowfish()
    triple_des_ciphertext = fire_eccg_block_003_and_004_triple_des()

    print("Blowfish ciphertext:", blowfish_ciphertext.hex())
    print("TripleDES ciphertext:", triple_des_ciphertext.hex())