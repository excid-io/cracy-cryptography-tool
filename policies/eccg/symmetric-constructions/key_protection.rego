package cbom.eccg.symmetric_constructions.key_protection

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.is_ae_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_siv_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_aes_key_wrap_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Protection"

#
# ---------------------------------------------------------
# ECCG-KP-001
# AES Key Wrap is an agreed key-protection scheme.
#
# ECCG classification: R (Recommended)
#
# Covered schemes:
# - AES-KW
# - AES-KWP
# - AES-Wrap-PKCS7
#
# CBOM limitation:
# - CBOMkit currently does not reliably detect AES Key Wrap
#   as a first-class "key-wrap" primitive.
# - Detection may depend on name-based heuristics.
#
# This rule records the ECCG classification when such a
# scheme is detected.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_aes_key_wrap_scheme(component)

    finding := build_finding(
        "ECCG-KP-001",
        "info",
        "AES Key Wrap (KW/KWP) is an agreed key-protection scheme.",
        component,
        {
            "status": "agreed",
            "scheme": "AES-KeyWrap"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KP-002
# SIV is an agreed key-protection scheme.
#
# ECCG classification: R (Recommended)
#
# Reference:
# - RFC 5297 (AES-SIV)
#
# CBOM limitation:
# - CBOMkit does not reliably model SIV as a key-protection
#   mechanism.
# - SIV is typically represented as an AEAD ("ae") primitive,
#   not as "key-wrap".
# - Detection therefore relies on name-based heuristics.
#
# This rule records the ECCG classification when SIV is used
# in a key-protection context.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_siv_scheme(component)

    finding := build_finding(
        "ECCG-KP-002",
        "info",
        "SIV (RFC5297) is an agreed key-protection scheme.",
        component,
        {
            "status": "agreed",
            "scheme": "SIV"
        }
    )
}