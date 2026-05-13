# configs/assymetric-atomic-primitives/tests/ec_dlog.py

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization


def serialize_ec_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def serialize_ec_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ec_key_agreement_example(curve):
    """
    EC-DLOG / elliptic-curve Diffie-Hellman example.

    This is intended for CBOMkit/static scanning only.

    The ECCG EC-DLOG section covers elliptic curves over prime fields.
    The public operation is scalar multiplication:

        Q = xP

    In pyca/cryptography, this is represented through elliptic-curve keys
    and ECDH exchange operations.
    """

    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()

    peer_private_key = ec.generate_private_key(curve)
    peer_public_key = peer_private_key.public_key()

    shared_secret = private_key.exchange(
        ec.ECDH(),
        peer_public_key,
    )

    return {
        "curve": curve.name,
        "key_size": curve.key_size,
        "private_key_pem": serialize_ec_private_key(private_key),
        "public_key_pem": serialize_ec_public_key(public_key),
        "shared_secret": shared_secret,
        "shared_secret_length": len(shared_secret),
    }


def ec_signature_example(curve):
    """
    EC-DLOG / ECDSA example.

    This helps scanners observe elliptic-curve use outside pure ECDH.
    ECDSA also relies on the elliptic-curve discrete logarithm problem.
    """

    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()

    message = b"CBOMkit EC-DLOG scanning example"

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256()),
    )

    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256()),
    )

    return {
        "curve": curve.name,
        "key_size": curve.key_size,
        "private_key_pem": serialize_ec_private_key(private_key),
        "public_key_pem": serialize_ec_public_key(public_key),
        "signature": signature,
        "signature_length": len(signature),
    }


def elliptic_curve_discrete_log_examples():
    #
    # EC-DLOG / elliptic-curve examples for CBOMkit scanning.
    #
    # ECCG table:
    #
    # Agreed elliptic curve parameters:
    #
    # Brainpool [RFC5639]
    # - BrainpoolP256r1  -> R
    # - BrainpoolP384r1  -> R
    # - BrainpoolP512r1  -> R
    #
    # NIST [FIPS186-4, Appendix D.1.2]
    # - NIST P-256       -> R
    # - NIST P-384       -> R
    # - NIST P-521       -> R
    #
    # FR [JORF]
    # - FRP256v1         -> R
    #
    # pyca/cryptography support note:
    # - BrainpoolP256R1, BrainpoolP384R1, BrainpoolP512R1 are supported.
    # - SECP256R1, SECP384R1, SECP521R1 are the pyca names for NIST P-256,
    #   P-384, and P-521.
    # - FRP256v1 is not exposed as a built-in curve class in pyca/cryptography.
    #   It is documented below for scanner mapping, but cannot be instantiated
    #   directly with this library.
    #
    # This file intentionally creates both:
    # - ECDH examples, for key agreement detection.
    # - ECDSA examples, for EC-DLOG primitive detection through signatures.
    #

    curves = {
        #
        # Brainpool curves [RFC5639]
        #
        "brainpoolP256r1": ec.BrainpoolP256R1(),
        "brainpoolP384r1": ec.BrainpoolP384R1(),
        "brainpoolP512r1": ec.BrainpoolP512R1(),

        #
        # NIST prime curves [FIPS186-4, Appendix D.1.2]
        #
        # pyca/cryptography names:
        # - SECP256R1 == NIST P-256 / prime256v1
        # - SECP384R1 == NIST P-384
        # - SECP521R1 == NIST P-521
        #
        "nistP256": ec.SECP256R1(),
        "nistP384": ec.SECP384R1(),
        "nistP521": ec.SECP521R1(),
    }

    examples = {}

    for label, curve in curves.items():
        examples[f"ecdh_{label}"] = {
            "primitive": "EC-DLOG",
            "operation": "ECDH",
            "classification": "R",
            **ec_key_agreement_example(curve),
        }

        examples[f"ecdsa_{label}"] = {
            "primitive": "EC-DLOG",
            "operation": "ECDSA",
            "classification": "R",
            **ec_signature_example(curve),
        }

    #
    # FRP256v1 scanner placeholder.
    #
    # ECCG lists FRP256v1 as recommended.
    # pyca/cryptography does not provide a built-in FRP256v1 curve class,
    # so this cannot be instantiated here.
    #
    # Keep these constants so source scanners can still observe the intended
    # algorithm/curve names.
    #
    frp256v1_scanner_metadata = {
        "primitive": "EC-DLOG",
        "curve_family": "FR [JORF]",
        "curve": "FRP256v1",
        "classification": "R",
        "pyca_cryptography_support": "not_available_as_builtin_curve",
        "scanner_names": [
            "FRP256v1",
            "FRP-256v1",
            "frp256v1",
        ],
    }

    examples["metadata_frp256v1"] = frp256v1_scanner_metadata

    return examples


if __name__ == "__main__":
    examples = elliptic_curve_discrete_log_examples()

    for name, material in examples.items():
        print(f"\n{name}")
        print(f"primitive={material.get('primitive')}")
        print(f"operation={material.get('operation', 'metadata-only')}")
        print(f"classification={material.get('classification')}")
        print(f"curve={material.get('curve')}")
        print(f"key_size={material.get('key_size', 'unknown')}")

        if "shared_secret_length" in material:
            print(f"shared_secret_length={material['shared_secret_length']}")

        if "signature_length" in material:
            print(f"signature_length={material['signature_length']}")

        if "public_key_pem" in material:
            print(material["public_key_pem"].decode())

        if "private_key_pem" in material:
            print(material["private_key_pem"].decode())

        if name == "metadata_frp256v1":
            print(f"curve_family={material['curve_family']}")
            print(f"pyca_cryptography_support={material['pyca_cryptography_support']}")
            print(f"scanner_names={material['scanner_names']}")