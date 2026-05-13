package cbom.eccg.symmetric_constructions.password_hashing

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_password_hashing_primitive

import data.cbom.eccg.symmetric_constructions.helpers.is_pbkdf2_component
import data.cbom.eccg.symmetric_constructions.helpers.is_pbkdf2_sha1_component
import data.cbom.eccg.symmetric_constructions.helpers.get_underlying_hash_component_from_kdf_or_unknown

default compliant := true
compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Password-Protection"

#
# --------------------------------------------------
# Rule ECCG-PWH-001
# PBKDF2 used for password hashing is an agreed mechanism.
# --------------------------------------------------
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_password_hashing_primitive(component)
    is_pbkdf2_component(component)
    not is_pbkdf2_sha1_component(component)

    note_ids := [
        "27-NumberOfIterations",
        "28-Salt"
    ]

    notes := [
        get_note(SECTION, SUBSECTION, id)
        | id := note_ids[_]
    ]

    finding := build_finding(
        "ECCG-PWH-001",
        "info",
        sprintf(
            "Password hashing mechanism '%s' is based on PBKDF2, which is the agreed password hashing mechanism",
            [component.name]
        ),
        component,
        {
            "scheme": "PBKDF2",
            "status": "agreed",
            "notes": notes,
        }
    )
}

#
# --------------------------------------------------
# Rule ECCG-PWH-002
# PBKDF2-SHA1 in password hashing context should be flagged.
#
# The ECCG password hashing section agrees PBKDF2 as a scheme,
# but in broader policy set SHA-1 is legacy and should not be
# recommended for new password hashing usage.
# --------------------------------------------------
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_password_hashing_primitive(component)
    is_pbkdf2_sha1_component(component)

    finding := build_finding(
        "ECCG-PWH-002",
        "high",
        "PBKDF2 is the agreed password hashing scheme, but PBKDF2-SHA1 relies on legacy SHA-1 and should not be used",
        component,
        {
            "scheme": "PBKDF2",
            "underlyingHash": "SHA1",
            "status": "not-recommended"
        }
    )
}

#
# --------------------------------------------------
# Rule ECCG-PWH-003
# Non-agreed password hashing schemes should be flagged.
#
# ECCG context:
# - PBKDF2 is the agreed password hashing mechanism.
# - Password hashing mechanisms not listed by ECCG should normally
#   be flagged for review / non-compliance.
#
# Current CBOM limitation:
# - CBOMkit currently represents password hashing mechanisms only
#   as generic key-derivation components.
# - The CBOM does not reliably expose whether a KDF is being used
#   specifically for password hashing, password verification, or
#   general-purpose key derivation.
#
# As a result:
# - A strict "non-agreed password hashing" rule is not implemented
#   here because it would incorrectly flag unrelated KDFs such as
#   HKDF, ANSI X9.63 KDF, or SP800-56 KDF when they are not used
#   for password hashing.
#
# This comment is retained intentionally to document the modeling
# limitation and avoid overclaiming policy coverage.
# --------------------------------------------------
#