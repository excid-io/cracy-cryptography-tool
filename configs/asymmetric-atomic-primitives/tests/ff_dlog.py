# configs/assymetric-atomic-primitives/tests/ff_dlog.py

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


def finite_field_discrete_log_examples():
    #
    # FF-DLOG / finite-field Diffie-Hellman examples.
    #
    # ECCG table:
    # - MODP / FFDHE groups of 3072, 4096, 6144, 8192 bits are Recommended.
    # - MODP / FFDHE 2048-bit groups are Legacy[2025].
    #
    # This file is intended for CBOM/scanner detection only.
    # It demonstrates finite-field DH parameter sizes using pyca/cryptography.
    #

    #
    # Legacy FF-DLOG group size: 2048-bit finite-field DH
    #
    legacy_parameters_2048 = dh.generate_parameters(
        generator=2,
        key_size=2048,
    )

    legacy_private_key_2048 = legacy_parameters_2048.generate_private_key()
    legacy_public_key_2048 = legacy_private_key_2048.public_key()

    legacy_peer_private_key_2048 = legacy_parameters_2048.generate_private_key()
    legacy_peer_public_key_2048 = legacy_peer_private_key_2048.public_key()

    legacy_shared_secret_2048 = legacy_private_key_2048.exchange(
        legacy_peer_public_key_2048
    )

    #
    # Recommended FF-DLOG group size: 3072-bit finite-field DH
    #
    recommended_parameters_3072 = dh.generate_parameters(
        generator=2,
        key_size=3072,
    )

    recommended_private_key_3072 = recommended_parameters_3072.generate_private_key()
    recommended_public_key_3072 = recommended_private_key_3072.public_key()

    recommended_peer_private_key_3072 = recommended_parameters_3072.generate_private_key()
    recommended_peer_public_key_3072 = recommended_peer_private_key_3072.public_key()

    recommended_shared_secret_3072 = recommended_private_key_3072.exchange(
        recommended_peer_public_key_3072
    )

    #
    # Recommended FF-DLOG group size: 4096-bit finite-field DH
    #
    recommended_parameters_4096 = dh.generate_parameters(
        generator=2,
        key_size=4096,
    )

    recommended_private_key_4096 = recommended_parameters_4096.generate_private_key()
    recommended_public_key_4096 = recommended_private_key_4096.public_key()

    recommended_peer_private_key_4096 = recommended_parameters_4096.generate_private_key()
    recommended_peer_public_key_4096 = recommended_peer_private_key_4096.public_key()

    recommended_shared_secret_4096 = recommended_private_key_4096.exchange(
        recommended_peer_public_key_4096
    )

    #
    # Serialize parameters/public keys so scanners can observe them.
    #
    legacy_parameters_2048_pem = legacy_parameters_2048.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )

    recommended_parameters_3072_pem = recommended_parameters_3072.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )

    recommended_parameters_4096_pem = recommended_parameters_4096.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    )

    legacy_public_key_2048_pem = legacy_public_key_2048.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    recommended_public_key_3072_pem = recommended_public_key_3072.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    recommended_public_key_4096_pem = recommended_public_key_4096.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "legacy_ffdlog_2048": {
            "parameters": legacy_parameters_2048_pem,
            "public_key": legacy_public_key_2048_pem,
            "shared_secret": legacy_shared_secret_2048,
        },
        "recommended_ffdlog_3072": {
            "parameters": recommended_parameters_3072_pem,
            "public_key": recommended_public_key_3072_pem,
            "shared_secret": recommended_shared_secret_3072,
        },
        "recommended_ffdlog_4096": {
            "parameters": recommended_parameters_4096_pem,
            "public_key": recommended_public_key_4096_pem,
            "shared_secret": recommended_shared_secret_4096,
        },
    }


if __name__ == "__main__":
    examples = finite_field_discrete_log_examples()

    for name, material in examples.items():
        print(f"\n{name}")
        print(material["parameters"].decode())
        print(material["public_key"].decode())
        print(f"shared_secret_length={len(material['shared_secret'])}")