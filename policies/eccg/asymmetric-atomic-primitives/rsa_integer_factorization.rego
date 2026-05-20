package cbom.eccg.asymmetric_atomic_primitives.rsa_integer_factorization

import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown

import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_rsa_primitive
import data.cbom.eccg.asymmetric_atomic_primitives.helpers.classify_rsa_modulus


SECTION = "Asymmetric-Atomic-Primitives"
SUBSECTION = "RSA-Integer-Factorization"

#
# ---------------------------------------------------------
# ECCG-RSA-001
# RSA primitive has recommended parameter size.
#
# ECCG classification: R
#
# Limitation:
# - CycloneDX 1.7 does not expose RSA public exponent e.
# - Therefore log2(e) > 16 cannot be verified from the CBOM.
# - This rule checks only the available modulus size n.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_rsa_primitive(component)

    n := get_parameter_set_identifier_to_number_or_unknown(component)
    n != "unknown"
    n >= 3000

    finding := build_finding(
        "ECCG-RSA-001",
        "info",
        sprintf(
            "RSA primitive detected with modulus size n=%d bits. Classified as recommended. The ECCG exponent condition log2(e) > 16 could not be verified from CycloneDX data.",
            [n]
        ),
        component,
        {
            "scheme": "RSA",
            "modulusBits": n,
            "status": "recommended",
            "classification": "R",
            "publicExponent": "unknown",
            "exponentCheck": "not_verifiable"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-RSA-002
# RSA primitive has legacy parameter size.
#
# ECCG classification: L
#
# Limitation:
# - CycloneDX 1.7 does not expose RSA public exponent e.
# - Therefore log2(e) > 16 cannot be verified from the CBOM.
# - This rule checks only the available modulus size n.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_rsa_primitive(component)

    n := get_parameter_set_identifier_to_number_or_unknown(component)
    n != "unknown"
    n >= 1900
    n < 3000

    note := get_note(SECTION, SUBSECTION, "30-LegacyRSA")

    finding := build_finding(
        "ECCG-RSA-002",
        "critical",
        sprintf(
            "RSA primitive detected with Legacy[2025] modulus size n=%d bits ( 1900 <= bits < 3000 ). The ECCG exponent condition log2(e) > 16 could not be verified from CycloneDX data.",
            [n]
        ),
        component,
        {
            "scheme": "RSA",
            "modulusBits": n,
            "status": "legacy",
            "classification": "L",
            "publicExponent": "unknown",
            "exponentCheck": "not_verifiable",
            "note": note
        }
    )
}