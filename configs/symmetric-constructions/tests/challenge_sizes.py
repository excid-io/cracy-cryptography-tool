# configs/symmetric-constructions/tests/symmetric_entity_authentication.py

import os
from cryptography.hazmat.primitives import hashes, hmac


def agreed_challenge_response_hmac():
    """
    Agreed challenge size:
    125 <= l

    Uses a 128-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(16)  # 16 bytes = 128 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def legacy_challenge_response_hmac():
    """
    Legacy challenge size:
    96 <= l < 125

    Uses a 96-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(12)  # 12 bytes = 96 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def not_agreed_challenge_response_hmac():
    """
    Not agreed by the table:
    l < 96

    Uses a 64-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(8)  # 8 bytes = 64 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def replay_vulnerable_fixed_challenge_response_hmac():
    """
    Bad example for Note 20-CollChallenge.

    The challenge is fixed, so it can be replayed.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = b"fixed-challenge!"  # 16 bytes = 128 bits, but predictable/reused

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def all_symmetric_entity_authentication_examples():
    return {
        "agreed_128_bit_challenge": agreed_challenge_response_hmac(),
        "legacy_96_bit_challenge": legacy_challenge_response_hmac(),
        "not_agreed_64_bit_challenge": not_agreed_challenge_response_hmac(),
        "replay_vulnerable_fixed_challenge": replay_vulnerable_fixed_challenge_response_hmac(),
    }
    # configs/symmetric-constructions/tests/symmetric_entity_authentication.py

import os
from cryptography.hazmat.primitives import hashes, hmac


def agreed_challenge_response_hmac():
    """
    Agreed challenge size:
    125 <= l

    Uses a 128-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(16)  # 16 bytes = 128 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def legacy_challenge_response_hmac():
    """
    Legacy challenge size:
    96 <= l < 125

    Uses a 96-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(12)  # 12 bytes = 96 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def not_agreed_challenge_response_hmac():
    """
    Not agreed by the table:
    l < 96

    Uses a 64-bit verifier-generated random challenge.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = os.urandom(8)  # 8 bytes = 64 bits

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def replay_vulnerable_fixed_challenge_response_hmac():
    """
    Bad example for Note 20-CollChallenge.

    The challenge is fixed, so it can be replayed.
    """
    key = b"shared-authentication-key-32bytes"
    challenge = b"fixed-challenge!"  # 16 bytes = 128 bits, but predictable/reused

    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(challenge)
    response = mac.finalize()

    return {
        "scheme": "challenge_response_hmac",
        "challenge_size_bits": len(challenge) * 8,
        "challenge": challenge,
        "response": response,
    }


def all_symmetric_entity_authentication_examples():
    return {
        "agreed_128_bit_challenge": agreed_challenge_response_hmac(),
        "legacy_96_bit_challenge": legacy_challenge_response_hmac(),
        "not_agreed_64_bit_challenge": not_agreed_challenge_response_hmac(),
        "replay_vulnerable_fixed_challenge": replay_vulnerable_fixed_challenge_response_hmac(),
    }