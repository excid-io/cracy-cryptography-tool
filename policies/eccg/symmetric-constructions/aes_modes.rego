package cbom.eccg.symmetric_constructions.aes_modes

import data.eccg.eccg_notes.notes

import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_symmetric_encryption_scheme
import data.cbom.eccg.helpers.build_finding

import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_symmetric_encryption_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_conditionally_agreed_symmetric_encryption_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_padding_sensitive_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_stream_mode_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_cbc_scheme


default compliant := true

compliant if count(findings) == 0

SECTION := "Symmetric-Constructions"
SUBSECTION := "Symmetric-Encryption-Schemes"

#
# Rule ECCG-SYM-ENC-001
# Flag schemes not in the agreed symmetric encryption scheme list.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    not is_agreed_symmetric_encryption_scheme(component)

    finding := build_finding(
        "ECCG-SYM-ENC-001",
        "critical",
        sprintf(
            "Symmetric encryption scheme '%s' is not in the agreed scheme list (CTR, OFB, CBC, CBC-CS, CFB). This does not necessarily mean that your code is unsafe, but should be flagged for a warning.",
            [component.name]
        ),
        component,
        {
            "mode": get_mode_or_unknown(component),
            "primitive": get_primitive_or_unknown(component)
        }
    )
}

#
# Rule ECCG-SYM-ENC-002
# All R* schemes are only conditionally recommended.
# Without additional integrity, standalone use is considered legacy.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_conditionally_agreed_symmetric_encryption_scheme(component)

    note := get_note(SECTION, SUBSECTION, "6-AddIntegrity")

    finding := build_finding(
        "ECCG-SYM-ENC-002",
        "warning",
        sprintf(
            "Scheme '%s' is only conditionally recommended; standalone use is legacy unless additional integrity is provided",
            [component.name]
        ),
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component),
            "status": "conditional"
        }
    )
}

#
# Rule ECCG-SYM-ENC-003
# IV warning.
# The note says modes with a constant or predictable IV are not accepted.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_agreed_symmetric_encryption_scheme(component)

    note := get_note(SECTION, SUBSECTION, "5-IVType")

    finding := build_finding(
        "ECCG-SYM-ENC-003",
        "warning",
        "Modes require a non-predictable IV",
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-SYM-ENC-004
# Stream-mode warning for CTR and OFB.
# The note says IV-key reuse must not cause keystream overlap.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_stream_mode_scheme(component)

    note := get_note(SECTION, SUBSECTION, "7-StreamMode")

    finding := build_finding(
        "ECCG-SYM-ENC-004",
        "warning",
        sprintf(
            "Scheme '%s' is a stream-mode construction; IV-key reuse must not cause keystream overlap",
            [component.name]
        ),
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-SYM-ENC-005
# Padding-related warning for padding-sensitive schemes.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_symmetric_encryption_scheme(component)
    is_padding_sensitive_scheme(component)

    note := get_note(SECTION, SUBSECTION, "8-Padding")

    finding := build_finding(
        "ECCG-SYM-ENC-005",
        "warning",
        sprintf(
            "Scheme '%s' requires careful padding handling; implementations should not expose padding-oracle behavior",
            [component.name]
        ),
        component,
        {
            "notes": note,
            "mode": get_mode_or_unknown(component)
        }
    )
}