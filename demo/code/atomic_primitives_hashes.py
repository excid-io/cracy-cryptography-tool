from cryptography.hazmat.primitives import hashes


def fire_eccg_hash_001_sha224():
    """
    Should fire ECCG-HASH-001.

    SHA-224 is explicitly legacy-only according to your REGO rule:
      is_hash_primitive(component)
      is_sha224(component)
    """

    digest = hashes.Hash(hashes.SHA224())
    digest.update(b"test message for SHA-224")

    return digest.finalize()


def fire_eccg_hash_002_sha512_224():
    """
    Should fire ECCG-HASH-002.

    SHA-512/224 is explicitly legacy-only according to your REGO rule:
      is_hash_primitive(component)
      is_sha512_224(component)
    """

    digest = hashes.Hash(hashes.SHA512_224())
    digest.update(b"test message for SHA-512/224")

    return digest.finalize()


def fire_eccg_hash_003_non_agreed_hash():
    """
    Should fire ECCG-HASH-003.

    MD5 is a hash primitive, but it should not be in the agreed hash list.
    This fires if your helpers do NOT classify MD5 as legacy_hash_component.

    Rule condition:
      is_hash_primitive(component)
      not is_legacy_hash_component(component)
      not is_agreed_hash_component(component)
    """

    digest = hashes.Hash(hashes.MD5())
    digest.update(b"test message for MD5")

    return digest.finalize()


if __name__ == "__main__":
    sha224_digest = fire_eccg_hash_001_sha224()
    sha512_224_digest = fire_eccg_hash_002_sha512_224()
    md5_digest = fire_eccg_hash_003_non_agreed_hash()

    print("SHA224:", sha224_digest.hex())
    print("SHA512_224:", sha512_224_digest.hex())
    print("MD5:", md5_digest.hex())