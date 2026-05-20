from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def fire_eccg_sym_enc_001_aes_ecb():
    """
    Should fire ECCG-SYM-ENC-001.

    AES-ECB is a symmetric encryption scheme, but ECB is not in the agreed
    scheme list used by the REGO rule:

      CTR, OFB, CBC, CBC-CS, CFB

    Therefore:
      is_symmetric_encryption_scheme(component)
      not is_agreed_symmetric_encryption_scheme(component)
    """

    key = b"K" * 16  # AES-128 key

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
    )

    encryptor = cipher.encryptor()

    # ECB requires input length to be a multiple of AES block size: 16 bytes.
    plaintext = b"A" * 16

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext


if __name__ == "__main__":
    ciphertext = fire_eccg_sym_enc_001_aes_ecb()
    print("AES-ECB ciphertext:", ciphertext.hex())