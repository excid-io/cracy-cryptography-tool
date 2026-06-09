package cbom.eccg.symmetric_constructions.key_protection

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.is_key_wrap_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_key_wrap_scheme

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Key-Protection"

#
# Rule ECCG-KP-001
# Non-agreed key-protection / key-wrap scheme detected.
#
# Key protection schemes are detected through is_key_wrap_scheme(component).
#
# Agreed key protection schemes:
# - AES Key Wrap / AES-KW
# - AES Key Wrap with Padding / AES-KWP
# - AES-SIV / SIV
#
# Any detected key-wrap / key-protection scheme that is not accepted by
# is_agreed_key_wrap_scheme(component) is reported as non-critical.
#
# This rule is intentionally non-critical because CBOM extraction may not always
# distinguish key wrapping, authenticated encryption, and generic algorithm names
# precisely. Review the finding before treating it as a confirmed violation.
#
findings contains finding if {
    component := input.components[_]

    is_key_wrap_primitive(component)
    not is_agreed_key_wrap_scheme(component)

    finding := build_finding(
        "ECCG-KP-001",
        "medium",
        sprintf(
            "Key protection scheme '%s' is not in the agreed key-protection list. Agreed schemes are AES Key Wrap, AES Key Wrap with Padding, and SIV. This might be a false positive since there is no way to distinguish key protection schemes from the CBOM.",
            [component.name]
        ),
        component,
        {
            "status": "not-agreed",
            "scheme": component.name,
            "mode": get_mode_or_unknown(component),
            "primitive": get_primitive_or_unknown(component),
            "agreedKeyProtectionSchemes": [
                "AES Key Wrap",
                "AES Key Wrap with Padding",
                "SIV"
            ]
        }
    )
}
