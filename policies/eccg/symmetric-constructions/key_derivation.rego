package cbom.eccg.symmetric_constructions.key_derivation

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_kdf_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_kdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_nist_sp800_56_abc_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_ansi_x963_kdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_pbkdf2_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_hkdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.get_kdf_underlying_hash_name_or_unknown
import data.cbom.eccg.symmetric_constructions.helpers.get_kdf_underlying_hash_parameter_size_or_unknown
import data.cbom.eccg.symmetric_constructions.helpers.get_pbkdf2_prf_or_unknown

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Derivation-Functions"

#
# ---------------------------------------------------------
# ECCG-KDF-001
# NIST SP800-56 ABC is an agreed key derivation function.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - none
#
# In the current CBOM sample, this scheme is emitted as
# "ConcatenationKDF". This rule records the agreed status and
# includes the underlying hash when recoverable through dependencies.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_nist_sp800_56_abc_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_size := get_kdf_underlying_hash_parameter_size_or_unknown(component)

    finding := build_finding(
        "ECCG-KDF-001",
        "info",
        "NIST SP800-56 ABC is an agreed key derivation function.",
        component,
        {
            "status": "agreed",
            "scheme": "NIST SP800-56 ABC",
            "underlyingHash": hash_name,
            "underlyingHashParameterSize": hash_size,
            "notes": []
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-002
# ANSI-X9.63-KDF is an agreed key derivation function.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - none
#
# In the current CBOM sample, this scheme is emitted as
# "ANSI X9.63". This rule records the agreed status and
# includes the underlying hash when recoverable through dependencies.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_ansi_x963_kdf_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_size := get_kdf_underlying_hash_parameter_size_or_unknown(component)

    finding := build_finding(
        "ECCG-KDF-002",
        "info",
        "ANSI-X9.63-KDF is an agreed key derivation function.",
        component,
        {
            "status": "agreed",
            "scheme": "ANSI-X9.63-KDF",
            "underlyingHash": hash_name,
            "underlyingHashParameterSize": hash_size,
            "notes": []
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-003
# PBKDF2 is an agreed key derivation function.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - Note 26 (PBKDF2-PRF)
#
# PBKDF2 is agreed by ECCG. In the current CBOM sample, this scheme
# is emitted as "PBKDF2-SHA256". This rule records the agreed status
# and includes the inferred PRF basis and underlying hash when
# recoverable through dependencies.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_pbkdf2_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_size := get_kdf_underlying_hash_parameter_size_or_unknown(component)
    prf := get_pbkdf2_prf_or_unknown(component)

    note := get_note(SECTION, SUBSECTION, "26-PBKDF2-PRF")

    finding := build_finding(
        "ECCG-KDF-003",
        "warning",
        sprintf(
            "PBKDF2 is an agreed key derivation function. Detected PRF basis: %s.",
            [prf]
        ),
        component,
        {
            "status": "agreed",
            "scheme": "PBKDF2",
            "underlyingHash": hash_name,
            "underlyingHashParameterSize": hash_size,
            "prf": prf,
            # Explicit ECCG note reference
            "notes": note
        }
    )
}


#
# ---------------------------------------------------------
# ECCG-KDF-004
# HKDF is an agreed key derivation function.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - none
#
# In the current CBOM sample, this scheme is emitted as
# "HKDF-SHA256". This rule records the agreed status and
# includes the underlying hash when recoverable through dependencies.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_hkdf_scheme(component)

    hash_name := get_kdf_underlying_hash_name_or_unknown(component)
    hash_size := get_kdf_underlying_hash_parameter_size_or_unknown(component)

    finding := build_finding(
        "ECCG-KDF-004",
        "info",
        "HKDF is an agreed key derivation function.",
        component,
        {
            "status": "agreed",
            "scheme": "HKDF",
            "underlyingHash": hash_name,
            "underlyingHashParameterSize": hash_size,
            "notes": []
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-005
# Generic agreed-KDF classification fallback.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - scheme-dependent
#
# This fallback exists for future-proofing in case CBOMkit emits a KDF
# component that is recognized as agreed by the helper set but is not
# yet covered by a more specific finding above. The explicit scheme
# rules should normally handle the current CBOM sample.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_agreed_kdf_scheme(component)

    not is_nist_sp800_56_abc_scheme(component)
    not is_ansi_x963_kdf_scheme(component)
    not is_pbkdf2_scheme(component)
    not is_hkdf_scheme(component)

    finding := build_finding(
        "ECCG-KDF-006",
        "info",
        "An agreed key derivation function was detected.",
        component,
        {
            "status": "agreed",
            "scheme": component.name,
            "underlyingHash": get_kdf_underlying_hash_name_or_unknown(component),
            "underlyingHashParameterSize": get_kdf_underlying_hash_parameter_size_or_unknown(component),
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KDF-006
# Generic KDF detection for visibility.
#
# ECCG linkage:
# - Applies to all detected KDF components
#
# Relevant notes:
# - scheme-dependent
#
# This optional visibility rule can help debug CBOMkit extraction by
# surfacing every KDF component seen by the policy. It excludes agreed
# KDFs already classified above, so it mainly helps identify future or
# non-table KDF variants.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_kdf_primitive(component)
    not is_agreed_kdf_scheme(component)

    finding := build_finding(
        "ECCG-KDF-006",
        "critical",
        "A key derivation function component was detected but is not currently classified as an agreed ECCG KDF by this policy. This doesn't mean that your code is unsafe, but should be flagged as non compliant.",
        component,
        {
            "status": "unclassified-kdf",
            "scheme": component.name,
            "underlyingHash": get_kdf_underlying_hash_name_or_unknown(component),
            "underlyingHashParameterSize": get_kdf_underlying_hash_parameter_size_or_unknown(component),
        }
    )
}