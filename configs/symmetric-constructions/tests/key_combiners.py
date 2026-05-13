# configs/symmetric-constructions/tests/key_combiners.py

from cryptography.hazmat.primitives import hashes


def _hash_concat(*parts: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    for part in parts:
        digest.update(part)
    return digest.finalize()


def catkdf_example():
    """
    Agreed key combiner: CatKDF [ETSI]

    Concatenate multiple shared secrets / key-establishment outputs and
    derive a combined key by hashing the concatenation together with
    context information.
    """
    secret_1 = b"classical-shared-secret-demo-1234"
    secret_2 = b"post-quantum-shared-secret-demo-5678"
    context = b"purpose:hybrid-key-combiner|scheme:catkdf|alg:SHA256"

    combined_input = secret_1 + secret_2
    combined_key = _hash_concat(combined_input, context)

    return {
        "scheme": "catkdf",
        "secret_1": secret_1,
        "secret_2": secret_2,
        "context": context,
        "combined_input": combined_input,
        "combined_key": combined_key,
    }


def caskdf_example():
    """
    Agreed key combiner: CasKDF [ETSI]

    Cascade-style combination of multiple shared secrets / key-establishment
    outputs, where one stage feeds into the next derivation step.
    """
    secret_1 = b"classical-shared-secret-demo-1234"
    secret_2 = b"post-quantum-shared-secret-demo-5678"
    context = b"purpose:hybrid-key-combiner|scheme:caskdf|alg:SHA256"

    stage_1 = _hash_concat(secret_1, context)
    combined_key = _hash_concat(stage_1, secret_2, context)

    return {
        "scheme": "caskdf",
        "secret_1": secret_1,
        "secret_2": secret_2,
        "context": context,
        "stage_1": stage_1,
        "combined_key": combined_key,
    }


def all_key_combiner_examples():
    return {
        "catkdf": catkdf_example(),
        "caskdf": caskdf_example(),
    }


if __name__ == "__main__":
    examples = all_key_combiner_examples()
    for name, result in examples.items():
        print(f"{name}: ok, combined {len(result['combined_key'])} bytes")