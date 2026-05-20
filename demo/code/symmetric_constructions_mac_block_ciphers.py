from cryptography.hazmat.primitives import hashes, hmac


def fire_eccg_hmac_002_hmac_sha1():
    """
    Should fire ECCG-HMAC-002.

    This uses HMAC with SHA-1 through pyca/cryptography:

      hmac.HMAC(..., hashes.SHA1())

    The REGO rule should classify this as:
      - a MAC primitive
      - an HMAC-SHA1 scheme
    """

    key = b"K" * 16

    mac = hmac.HMAC(
        key=key,
        algorithm=hashes.SHA1(),
    )

    mac.update(b"message authenticated with HMAC-SHA1")

    tag = mac.finalize()
    return tag


if __name__ == "__main__":
    tag = fire_eccg_hmac_002_hmac_sha1()
    print("HMAC-SHA1 tag:", tag.hex())