from cryptography.hazmat.primitives import hashes, hmac


def fire_eccg_hash_001_sha224_via_hmac():
    """
    Target: ECCG-HASH-001

    Uses SHA224 through pyca/cryptography HMAC.
    CBOMkit may be more likely to emit the underlying hash primitive
    when the hash is used inside HMAC rather than as a bare digest.
    """

    mac = hmac.HMAC(
        key=b"K" * 32,
        algorithm=hashes.SHA224(),
    )

    mac.update(b"message using SHA-224 inside HMAC")
    return mac.finalize()


def fire_eccg_hash_002_sha512_224_via_hmac():
    """
    Target: ECCG-HASH-002

    Uses SHA512/224 through pyca/cryptography HMAC.
    """

    mac = hmac.HMAC(
        key=b"K" * 32,
        algorithm=hashes.SHA512_224(),
    )

    mac.update(b"message using SHA-512/224 inside HMAC")
    return mac.finalize()


def fire_eccg_hash_003_non_agreed_hash_via_hmac():
    """
    Target: ECCG-HASH-003

    SM3 is a hash primitive exposed by pyca/cryptography.
    It should not be in your agreed ECCG hash list, and it is less likely
    than MD5/SHA1 to be classified as a legacy hash by your helper.
    """

    mac = hmac.HMAC(
        key=b"K" * 32,
        algorithm=hashes.SM3(),
    )

    mac.update(b"message using SM3 inside HMAC")
    return mac.finalize()


if __name__ == "__main__":
    sha224_mac = fire_eccg_hash_001_sha224_via_hmac()
    sha512_224_mac = fire_eccg_hash_002_sha512_224_via_hmac()
    sm3_mac = fire_eccg_hash_003_non_agreed_hash_via_hmac()

    print("HMAC-SHA224:", sha224_mac.hex())
    print("HMAC-SHA512_224:", sha512_224_mac.hex())
    print("HMAC-SM3:", sm3_mac.hex())