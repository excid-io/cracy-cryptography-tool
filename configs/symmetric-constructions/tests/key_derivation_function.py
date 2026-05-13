# configs/symmetric-constructions/tests/key_derivation_functions.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF


def nist_sp800_56abc_example():
    """
    Agreed scheme: NIST SP800-56 ABC

    Demonstrates a NIST-style concatenation KDF, suitable as a practical
    test example for SP800-56A/B/C-style key derivation from shared secret
    material plus context information.
    """
    shared_secret = b"shared-secret-material-32bytes!!"
    otherinfo = b"alg:AES-256|partyU:alice|partyV:bob|purpose:kdf-test"

    kdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=otherinfo,
    )
    derived_key = kdf.derive(shared_secret)

    return {
        "scheme": "nist-sp800-56-abc",
        "shared_secret": shared_secret,
        "otherinfo": otherinfo,
        "derived_key": derived_key,
    }


def ansi_x963_kdf_example():
    """
    Agreed scheme: ANSI-X9.63-KDF

    Demonstrates the X9.63 KDF using a shared secret and shared info.
    """
    shared_secret = b"ecdh-shared-secret-demo-value-1234"
    sharedinfo = b"alg:AES-128|apu:alice|apv:bob|purpose:key-wrap"

    kdf = X963KDF(
        algorithm=hashes.SHA256(),
        length=32,
        sharedinfo=sharedinfo,
    )
    derived_key = kdf.derive(shared_secret)

    return {
        "scheme": "ansi-x9.63-kdf",
        "shared_secret": shared_secret,
        "sharedinfo": sharedinfo,
        "derived_key": derived_key,
    }


def pbkdf2_example():
    """
    Agreed scheme: PBKDF2 [RFC8018]

    Relevant note:
    - Note 26-PBKDF2-PRF

    This example instantiates PBKDF2 with HMAC-SHA256 as the PRF.
    The password length is kept below the HMAC block size to avoid the
    prehashing caveat described in Note 26.
    """
    password = b"correct-horse-battery"  # shorter than SHA-256 HMAC block size
    salt = b"demo-salt-123456"
    iterations = 100_000

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    derived_key = kdf.derive(password)

    return {
        "scheme": "pbkdf2",
        "password": password,
        "salt": salt,
        "iterations": iterations,
        "prf": "HMAC-SHA256",
        "derived_key": derived_key,
        "note": "26-PBKDF2-PRF",
    }


def hkdf_example():
    """
    Agreed scheme: HKDF [RFC5869]

    Demonstrates HKDF extract-and-expand using a salt and application info.
    """
    ikm = b"input-keying-material-for-hkdf-demo"
    salt = b"hkdf-salt-demo"
    info = b"alg:ChaCha20|purpose:session-key|context:test"

    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    derived_key = kdf.derive(ikm)

    return {
        "scheme": "hkdf",
        "ikm": ikm,
        "salt": salt,
        "info": info,
        "derived_key": derived_key,
    }


def all_key_derivation_function_examples():
    return {
        "nist_sp800_56abc": nist_sp800_56abc_example(),
        "ansi_x963_kdf": ansi_x963_kdf_example(),
        "pbkdf2": pbkdf2_example(),
        "hkdf": hkdf_example(),
    }


if __name__ == "__main__":
    examples = all_key_derivation_function_examples()
    for name, result in examples.items():
        print(f"{name}: ok, derived {len(result['derived_key'])} bytes")