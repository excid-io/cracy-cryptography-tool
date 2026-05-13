# configs/asymmetric-primitives/tests/rsa_integer_factorization.py

from cryptography.hazmat.primitives.asymmetric import rsa


def rsa_agreed_3072_bit_example():
    """
    ECCG agreed RSA primitive size:
    n >= 3000 bits and log2(e) > 16

    Uses:
    - modulus size: 3072 bits
    - public exponent: 65537
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    return {
        "scheme": "RSA",
        "status": "agreed",
        "modulus_bits": numbers.n.bit_length(),
        "public_exponent": numbers.e,
        "public_exponent_bits": numbers.e.bit_length(),
    }


def rsa_legacy_2048_bit_example():
    """
    ECCG legacy RSA primitive size:
    n >= 1900 bits and log2(e) > 16, but below 3000 bits.

    Uses:
    - modulus size: 2048 bits
    - public exponent: 65537
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    return {
        "scheme": "RSA",
        "status": "legacy",
        "modulus_bits": numbers.n.bit_length(),
        "public_exponent": numbers.e,
        "public_exponent_bits": numbers.e.bit_length(),
    }


def all_rsa_integer_factorization_examples():
    return {
        "rsa_agreed_3072_bit": rsa_agreed_3072_bit_example(),
        "rsa_legacy_2048_bit": rsa_legacy_2048_bit_example(),
    }


if __name__ == "__main__":
    for name, result in all_rsa_integer_factorization_examples().items():
        print(
            f"{name}: modulus={result['modulus_bits']} bits, "
            f"e={result['public_exponent']} "
            f"({result['public_exponent_bits']} bits), "
            f"status={result['status']}"
        )