package cbom.eccg.asymmetric_atomic_primitives.ff_dlog

import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown

import data.cbom.eccg.asymmetric_atomic_primitives.helpers.is_ffdlog_primitive

SECTION = "Asymmetric-Atomic-Primitives"
SUBSECTION = "FF-DLOG"

#
# ---------------------------------------------------------
# ECCG-FFDLOG-001
# FF-DLOG primitive has recommended parameter size.
#
# ECCG classification: R
#
# Applies to:
# - 3072-bit MODP Group
# - 4096-bit MODP Group
# - 6144-bit MODP Group
# - 8192-bit MODP Group
# - 3072-bit FFDHE Group
# - 4096-bit FFDHE Group
# - 6144-bit FFDHE Group
# - 8192-bit FFDHE Group
#
# ECCG note:
# - For all agreed subgroups, r = q = (p - 1) / 2.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ffdlog_primitive(component)

    p_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    p_bits != "unknown"

    p_bits >= 3000

    finding := build_finding(
        "ECCG-FFDLOG-001",
        "info",
        sprintf(
            "FF-DLOG primitive detected with group size p=%d bits. Classified as recommended.",
            [p_bits]
        ),
        component,
        {
            "scheme": "FF-DLOG",
            "groupBits": p_bits,
            "status": "recommended",
            "classification": "R",
            "subgroupCondition": "r = q = (p - 1) / 2"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-FFDLOG-002
# FF-DLOG primitive has legacy parameter size.
#
# ECCG classification: L[2025]
#
# Applies to:
# - 2048-bit MODP Group
# - 2048-bit FFDHE Group
#
# ECCG notes:
# - 33-Precomputation
# - 34-LegacyFF-DLOG
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_ffdlog_primitive(component)

    p_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    p_bits != "unknown"

    p_bits >= 1900
    p_bits < 3000

    precomputation_note := get_note(SECTION, SUBSECTION, "33-Precomputation")
    legacy_note := get_note(SECTION, SUBSECTION, "34-LegacyFF-DLOG")

    finding := build_finding(
        "ECCG-FFDLOG-002",
        "critical",
        sprintf(
            "FF-DLOG primitive detected with legacy group size p=%d bits. Classified as Legacy[2025].",
            [p_bits]
        ),
        component,
        {
            "scheme": "FF-DLOG",
            "groupBits": p_bits,
            "status": "legacy",
            "classification": "L[2025]",
            "subgroupCondition": "r = q = (p - 1) / 2",
            "notes": {
                "precomputation": precomputation_note,
                "legacy": legacy_note
            }
        }
    )
}