package cbom.eccg.symmetric_constructions.key_derivation

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_kdf_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_kdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_pbkdf2_scheme
import data.cbom.eccg.symmetric_constructions.helpers.get_kdf_underlying_hash_name_or_unknown
import data.cbom.eccg.symmetric_constructions.helpers.get_kdf_underlying_hash_parameter_size_or_unknown

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Derivation-Functions"

#
# ---------------------------------------------------------
# ECCG-KDF-001
# HKDF, PBKDF2, ANSI-X9.63-KDF, and NIST SP800-56A/B/C
# are the only recommended symmetric key derivation mechanisms.
#
# ECCG classification: non-agreed KDF usage
#
# This rule detects KDF schemes that are not one of:
# - NIST SP800-56A/B/C
# - ANSI-X9.63-KDF
# - PBKDF2
# - HKDF
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    not is_agreed_kdf_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_size := get_kdf_underlying_hash_parameter_size_or_unknown(component)

    finding := build_finding(
        "ECCG-KDF-001",
        "critical",
        "HKDF, PBKDF2, ANSI-X9.63-KDF, and derivation methods defined in NIST SP800-56A/B/C are the only recommended symmetric key derivation mechanisms.",
        component,
        {
            "status": "notAgreed",
            "scheme": object.get(component, "name", "unknown"),
            "underlyingHash": hash_name,
            "underlyingHashParameterSize": hash_size,
            "notes": []
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-002
# With PBKDF2, HMAC is used as pseudo random function. The master
# secret length should be equal to the hash function message block length.
#
# Relevant notes:
# - Note 26 (PBKDF2-PRF)
#
# This rule detects PBKDF2 use where the master secret length is known
# and does not match the underlying hash function message block length.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_pbkdf2_scheme(component)

    note := get_note(SECTION, SUBSECTION, "26-PBKDF2-PRF")

    finding := build_finding(
        "ECCG-KDF-002",
        "warning",
        "With PBKDF2, HMAC is used as pseudo random function. The master secret length should be equal to the hash function message block length.",
        component,
        {
            "status": "notRecommended",
            "scheme": "PBKDF2",
            "notes": note
        }
    )
}