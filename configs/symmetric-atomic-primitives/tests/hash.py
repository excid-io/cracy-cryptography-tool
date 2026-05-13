# configs/symmetric-atomic-primitives/tests/hash_lengths_pyca.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash, ConcatKDFHMAC
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def pyca_hash_direct_examples():
    # Legacy / disallowed according to ECCG
    sha224_obj = hashes.Hash(hashes.SHA224())
    sha224_obj.update(b"data")
    digest_sha224 = sha224_obj.finalize()

    sha512_224_obj = hashes.Hash(hashes.SHA512_224())
    sha512_224_obj.update(b"data")
    digest_sha512_224 = sha512_224_obj.finalize()

    # Allowed according to ECCG
    sha256_obj = hashes.Hash(hashes.SHA256())
    sha256_obj.update(b"data")
    digest_sha256 = sha256_obj.finalize()

    sha384_obj = hashes.Hash(hashes.SHA384())
    sha384_obj.update(b"data")
    digest_sha384 = sha384_obj.finalize()

    sha512_obj = hashes.Hash(hashes.SHA512())
    sha512_obj.update(b"data")
    digest_sha512 = sha512_obj.finalize()

    sha512_256_obj = hashes.Hash(hashes.SHA512_256())
    sha512_256_obj.update(b"data")
    digest_sha512_256 = sha512_256_obj.finalize()

    sha3_256_obj = hashes.Hash(hashes.SHA3_256())
    sha3_256_obj.update(b"data")
    digest_sha3_256 = sha3_256_obj.finalize()

    sha3_384_obj = hashes.Hash(hashes.SHA3_384())
    sha3_384_obj.update(b"data")
    digest_sha3_384 = sha3_384_obj.finalize()

    sha3_512_obj = hashes.Hash(hashes.SHA3_512())
    sha3_512_obj.update(b"data")
    digest_sha3_512 = sha3_512_obj.finalize()

    # External / non-ECCG hash (should likely be flagged by policy)
    blake2b_obj = hashes.Hash(hashes.BLAKE2b(64))
    blake2b_obj.update(b"data")
    digest_blake2b = blake2b_obj.finalize()

    return (
        digest_sha224,
        digest_sha512_224,
        digest_sha256,
        digest_sha384,
        digest_sha512,
        digest_sha512_256,
        digest_sha3_256,
        digest_sha3_384,
        digest_sha3_512,
        digest_blake2b,
    )


def pyca_hmac_examples():
    key = b"k" * 32

    # Legacy / disallowed
    hmac_sha224 = HMAC(key, hashes.SHA224())
    hmac_sha224.update(b"message")
    tag_sha224 = hmac_sha224.finalize()

    hmac_sha512_224 = HMAC(key, hashes.SHA512_224())
    hmac_sha512_224.update(b"message")
    tag_sha512_224 = hmac_sha512_224.finalize()

    # Allowed
    hmac_sha256 = HMAC(key, hashes.SHA256())
    hmac_sha256.update(b"message")
    tag_sha256 = hmac_sha256.finalize()

    hmac_sha384 = HMAC(key, hashes.SHA384())
    hmac_sha384.update(b"message")
    tag_sha384 = hmac_sha384.finalize()

    hmac_sha512 = HMAC(key, hashes.SHA512())
    hmac_sha512.update(b"message")
    tag_sha512 = hmac_sha512.finalize()

    hmac_sha512_256 = HMAC(key, hashes.SHA512_256())
    hmac_sha512_256.update(b"message")
    tag_sha512_256 = hmac_sha512_256.finalize()

    # External / non-ECCG hash
    hmac_blake2b = HMAC(key, hashes.BLAKE2b(64))
    hmac_blake2b.update(b"message")
    tag_blake2b = hmac_blake2b.finalize()

    return (
        tag_sha224,
        tag_sha512_224,
        tag_sha256,
        tag_sha384,
        tag_sha512,
        tag_sha512_256,
        tag_blake2b,
    )


def pyca_kdf_examples():
    key_material = b"input key material"
    salt = b"salt"
    otherinfo = b"context"

    # HKDF
    hkdf_sha224 = HKDF(algorithm=hashes.SHA224(), length=32, salt=salt, info=otherinfo)
    hkdf_sha224_key = hkdf_sha224.derive(key_material)

    hkdf_sha512_224 = HKDF(algorithm=hashes.SHA512_224(), length=32, salt=salt, info=otherinfo)
    hkdf_sha512_224_key = hkdf_sha512_224.derive(key_material)

    hkdf_sha256 = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=otherinfo)
    hkdf_sha256_key = hkdf_sha256.derive(key_material)

    hkdf_blake2b = HKDF(algorithm=hashes.BLAKE2b(64), length=32, salt=salt, info=otherinfo)
    hkdf_blake2b_key = hkdf_blake2b.derive(key_material)

    # PBKDF2
    pbkdf2_sha224 = PBKDF2HMAC(algorithm=hashes.SHA224(), length=32, salt=salt, iterations=1000)
    pbkdf2_sha224_key = pbkdf2_sha224.derive(b"password")

    pbkdf2_sha512_224 = PBKDF2HMAC(algorithm=hashes.SHA512_224(), length=32, salt=salt, iterations=1000)
    pbkdf2_sha512_224_key = pbkdf2_sha512_224.derive(b"password")

    pbkdf2_sha256 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)
    pbkdf2_sha256_key = pbkdf2_sha256.derive(b"password")

    pbkdf2_blake2b = PBKDF2HMAC(algorithm=hashes.BLAKE2b(64), length=32, salt=salt, iterations=1000)
    pbkdf2_blake2b_key = pbkdf2_blake2b.derive(b"password")

    # ConcatKDFHash
    concat_hash_sha224 = ConcatKDFHash(algorithm=hashes.SHA224(), length=32, otherinfo=otherinfo)
    concat_hash_sha224_key = concat_hash_sha224.derive(key_material)

    concat_hash_sha512_224 = ConcatKDFHash(algorithm=hashes.SHA512_224(), length=32, otherinfo=otherinfo)
    concat_hash_sha512_224_key = concat_hash_sha512_224.derive(key_material)

    concat_hash_sha256 = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=otherinfo)
    concat_hash_sha256_key = concat_hash_sha256.derive(key_material)

    concat_hash_blake2b = ConcatKDFHash(algorithm=hashes.BLAKE2b(64), length=32, otherinfo=otherinfo)
    concat_hash_blake2b_key = concat_hash_blake2b.derive(key_material)

    # ConcatKDFHMAC
    concat_hmac_sha224 = ConcatKDFHMAC(algorithm=hashes.SHA224(), length=32, salt=salt, otherinfo=otherinfo)
    concat_hmac_sha224_key = concat_hmac_sha224.derive(key_material)

    concat_hmac_sha512_224 = ConcatKDFHMAC(algorithm=hashes.SHA512_224(), length=32, salt=salt, otherinfo=otherinfo)
    concat_hmac_sha512_224_key = concat_hmac_sha512_224.derive(key_material)

    concat_hmac_sha256 = ConcatKDFHMAC(algorithm=hashes.SHA256(), length=32, salt=salt, otherinfo=otherinfo)
    concat_hmac_sha256_key = concat_hmac_sha256.derive(key_material)

    concat_hmac_blake2b = ConcatKDFHMAC(algorithm=hashes.BLAKE2b(64), length=32, salt=salt, otherinfo=otherinfo)
    concat_hmac_blake2b_key = concat_hmac_blake2b.derive(key_material)

    # ANSI X9.63 KDF
    x963_sha224 = X963KDF(algorithm=hashes.SHA224(), length=32, sharedinfo=otherinfo)
    x963_sha224_key = x963_sha224.derive(key_material)

    x963_sha512_224 = X963KDF(algorithm=hashes.SHA512_224(), length=32, sharedinfo=otherinfo)
    x963_sha512_224_key = x963_sha512_224.derive(key_material)

    x963_sha256 = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=otherinfo)
    x963_sha256_key = x963_sha256.derive(key_material)

    x963_blake2b = X963KDF(algorithm=hashes.BLAKE2b(64), length=32, sharedinfo=otherinfo)
    x963_blake2b_key = x963_blake2b.derive(key_material)

    return (
        hkdf_sha224_key,
        hkdf_sha512_224_key,
        hkdf_sha256_key,
        hkdf_blake2b_key,
        pbkdf2_sha224_key,
        pbkdf2_sha512_224_key,
        pbkdf2_sha256_key,
        pbkdf2_blake2b_key,
        concat_hash_sha224_key,
        concat_hash_sha512_224_key,
        concat_hash_sha256_key,
        concat_hash_blake2b_key,
        concat_hmac_sha224_key,
        concat_hmac_sha512_224_key,
        concat_hmac_sha256_key,
        concat_hmac_blake2b_key,
        x963_sha224_key,
        x963_sha512_224_key,
        x963_sha256_key,
        x963_blake2b_key,
    )