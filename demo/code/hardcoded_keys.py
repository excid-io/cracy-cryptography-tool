from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


PRIVATE_KEY_PEM = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGf+QB9R3MpYQg
RDSdVPTo+zPxYC0JwHeiIUh4y2jeVeOaOWhQCvsrMs7a83YPZuu9MdHXDg2APebN
zUxm50rFIQfzJ3VTth9+ZdUtPQgckXdwkeypulLiJfRDSgRqICMdmL0NLOc2IqPN
X5ifo87nMgf/E91bl8xu4WSVtoD2pgBQBNyr+YKh/cLmKsynmbzUT285Dvm1SqAI
t9yLr3cNvTyq+HIZ3WPIMT7g5h7JbckeGtVPCfR+11uzFY3w3Ur9kHCiaz3VUfGb
lNF+7bXQjHh8JkHzcb7Fl7UOp2AdtrryDrV5Q1JDMIwL+uh5UvUkzM77erwxv0QY
wjXhrZVZAgMBAAECggEAI5ZLJPSyhn2IHhbMTgasr9ZVfilNecmZSSZpbUqefvns
B7rSEkOduyVtQ4DRgjpj+jPj2Ifq8LpoVi4/y9UcqRHecH/6/2qP4+PS37zo5uJH
hRWMVfOTJ3tBewzalMI1OXmoLyQFQcXdExVX8gr2ralhGKCRl3m0C476LwMcxNs2
B2KzoyAyk68Gaw89BXlySpWhHeRX1gESUcri+CMrEOFYWDdYEJl7Mlg+s3SAK44L
d0MLMOdXftIYcEUcetAi93mfUKaJljuYch5z8XsX01ePTynPs/IGA/9Ij95UxLr3
T4jW0OIu1T0w3YLuNxETYbyUZ3/Tu5YRR/w3Qj7Q+QKBgQDv9nIcaD3A0dvklk4R
q88lnMmbhY8UudDYJPm0dJqn2V1w6lbpwIqOsW+U18D4neiQyheeIe4zzOtd0NlU
YsSBD7lseUEfHGFwceKo1OapH6MvTdtGW5eNQ6wYvhNcvhkH1pBm3XIr2vjHF439
b98N9N2y4ZFnh2IIW70IWFwtHQKBgQDTxAwGAFijaQSBsxUEsvyncsnNN/6IfrJp
ftDHn1/HLLIg42wtnQS0WFcTVWNthmevi9r8Fn3YYA0EVgFsjUnDMa+xdTgle1RY
S2S+gLdlclD+hNJrwMbFJMT6mYb7GoJ/CJ8fkCvWqgR/4cSymwu5Xu6SqObwmvFJ
a5C0NbngbQKBgQDU4AFNOCCIXOPA/qIVRSCIEnY7tJlA3rLp/KtUrhjBDLC7Sfh+
d+OzQK9nEJvNMnCtecrH6vvhEko+uNcD6HbAs81f8JWX3tqGIVHdSrmxkTJ39Y6v
9PMWS9FxRbXxkWatMGh8CLmPNDt8i2XYThVH0VGXrkoK2Oxb0953d8OV9QKBgHKE
tX/VVhngo+hD4RzuckVXhRwuqL5FzdPRGbSqUlBSsm2orwqnvDCPCV/SMHe9VHsR
ZbYnr5yArOloXVLHwVkGmJ2d52QVotIwy2VeFE+PF4/cYjKVSKi6Lq/asK1Ac8ug
7PRTsfFfdhl2DToNMLTpSpkTL/hzwgJTYiiiWUetAoGBALJJzU0C//C9+WvgH0R9
48uUKK3kbygV54VYYwKBGDbUYuKTB7jLMQKybrtqH1AlUxWjNgXVHtlkXORdfjv9
gjEe5huPZXCpX4h2oxl4mRyqRkPT7joaz8loHfwxU84fi5loy4t/l6aqxvB0PEZT
MZQwcqLnr4cZCHjOsqW6iOLP
-----END PRIVATE KEY-----"""


PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxn/kAfUdzKWEIEQ0nVT0
6Psz8WAtCcB3oiFIeMto3lXjmjloUAr7KzLO2vN2D2brvTHR1w4NgD3mzc1MZudK
xSEH8yd1U7YffmXVLT0IHJF3cJHsqbpS4iX0Q0oEaiAjHZi9DSznNiKjzV+Yn6PO
5zIH/xPdW5fMbuFklbaA9qYAUATcq/mCof3C5irMp5m81E9vOQ75tUqgCLfci693
Db08qvhyGd1jyDE+4OYeyW3JHhrVTwn0ftdbsxWN8N1K/ZBwoms91VHxm5TRfu21
0Ix4fCZB83G+xZe1DqdgHba68g61eUNSQzCMC/roeVL1JMzO+3q8Mb9EGMI14a2V
WQIDAQAB
-----END PUBLIC KEY-----"""


def load_hardcoded_private_key():
    """
    Loads a hardcoded RSA-2048 private key from source code.
    This is intentionally insecure and should only be used for CBOMkit testing.
    """

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PEM,
        password=None,
    )


def load_hardcoded_public_key():
    """
    Loads a hardcoded RSA-2048 public key from source code.
    """

    return serialization.load_pem_public_key(PUBLIC_KEY_PEM)


def fire_eccg_rsa_002_with_hardcoded_public_key():
    """
    Performs RSA-OAEP encryption using the hardcoded RSA-2048 public key.

    Expected rule:
      ECCG-RSA-002

    Expected reason:
      RSA modulus is 2048 bits, which is within:
        1900 <= n < 3000
    """

    public_key = load_hardcoded_public_key()

    ciphertext = public_key.encrypt(
        b"message encrypted with hardcoded RSA-2048 public key",
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return ciphertext


def fire_eccg_rsa_002_with_hardcoded_private_key():
    """
    Performs RSA-PSS signing using the hardcoded RSA-2048 private key.

    This gives CBOMkit another RSA usage site to detect.
    """

    private_key = load_hardcoded_private_key()

    signature = private_key.sign(
        b"message signed with hardcoded RSA-2048 private key",
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return signature


if __name__ == "__main__":
    private_key = load_hardcoded_private_key()
    public_key = load_hardcoded_public_key()

    public_numbers = public_key.public_numbers()

    ciphertext = fire_eccg_rsa_002_with_hardcoded_public_key()
    signature = fire_eccg_rsa_002_with_hardcoded_private_key()

    print("RSA modulus bit length:", public_numbers.n.bit_length())
    print("RSA public exponent:", public_numbers.e)
    print("RSA-OAEP ciphertext length:", len(ciphertext))
    print("RSA-PSS signature length:", len(signature))