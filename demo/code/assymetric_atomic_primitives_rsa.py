from cryptography.hazmat.primitives.asymmetric import rsa


def fire_eccg_rsa_002_legacy_rsa_2048():
    """
    Should fire ECCG-RSA-002.

    The REGO rule flags RSA primitives with:

      1900 <= modulusBits < 3000

    A 2048-bit RSA key falls in that legacy range.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    return private_key, public_key


if __name__ == "__main__":
    private_key, public_key = fire_eccg_rsa_002_legacy_rsa_2048()

    numbers = public_key.public_numbers()

    print("RSA modulus bit length:", numbers.n.bit_length())
    print("RSA public exponent:", numbers.e)