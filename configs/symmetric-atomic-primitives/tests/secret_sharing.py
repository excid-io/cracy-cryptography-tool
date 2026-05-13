"""
Semgrep test file for crypto.secretsharing.require-shamir

Run with:
  semgrep -c semgrep-secretsharing.yml tests/require_shamir_test.py
"""

def bad_string_split(secret: str):
    # Ad-hoc string splitting of a secret
    parts = secret.split(":")          # ruleid: crypto.secretsharing.require-shamir
    return parts


def bad_byte_slicing(secret: bytes):
    # Manual slicing of secret bytes
    a = secret[0:8]                    # ruleid: crypto.secretsharing.require-shamir
    b = secret[8:16]
    return a, b


def bad_textwrap(secret: str):
    import textwrap
    # Chunking a secret into pieces
    chunks = textwrap.wrap(secret, 8)  # ruleid: crypto.secretsharing.require-shamir
    return chunks


def bad_base64_split(secret: bytes):
    import base64
    encoded = base64.b64encode(secret).decode("ascii")
    parts = encoded.split(".")         # ruleid: crypto.secretsharing.require-shamir
    return parts


def bad_xor_sharing(a: int, b: int):
    # XOR-based "sharing"
    return a ^ b                       # ruleid: crypto.secretsharing.require-shamir


def bad_append_shares(secret: bytes):
    shares = []
    shares.append(secret[:4])          # ruleid: crypto.secretsharing.require-shamir
    shares.append(secret[4:])
    return shares



def good_shamir_split(secret: bytes):
    from Crypto.Protocol.SecretSharing import Shamir
    # Proper Shamir Secret Sharing
    shares = Shamir.split(2, 3, secret)  # ok: crypto.secretsharing.require-shamir
    return shares


def good_shamir_combine(shares):
    from Crypto.Protocol.SecretSharing import Shamir
    return Shamir.combine(shares)        # ok: crypto.secretsharing.require-shamir


def unrelated_string_logic(x: str):
    # Not secret sharing
    return x.upper()                     # ok: crypto.secretsharing.require-shamir
