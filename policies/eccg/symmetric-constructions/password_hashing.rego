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
# PBKDF2 is the only agreed algorithm for password hashing.
# --------------------------------------------------
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_password_hashing_primitive(component)
    not is_pbkdf2_component(component)
    #not is_pbkdf2_sha1_component(component)

    #note_ids := [
    #    "27-NumberOfIterations",
    #    "28-Salt"
    #]

    #notes := [
    #    get_note(SECTION, SUBSECTION, id)
    #    | id := note_ids[_]
    #]

    finding := build_finding(
        "ECCG-PWH-001",
        "warning",
        sprintf(
            "Password hashing mechanism '%s' is based on PBKDF2, which is the agreed password hashing mechanism. Note that there is no way to differentiate, whether this is a KDF or a password hash from the CBOM alone.",
            [component.name]
        ),
        component,
        {
            "scheme": "PBKDF2",
            "status": "agreed",
            #"notes": notes,
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-PWH-002
# PBKDF2 must use a random salt with length >= 128 bits.
#
# ECCG classification: warning
#
# Detection:
# - Simply detects PBKDF2 usage and emits the warning message.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_password_hashing_primitive(component)
    is_pbkdf2_component(component)

    note := get_note(SECTION, SUBSECTION, "28-Salt")

    finding := build_finding(
        "ECCG-PWH-002",
        "warning",
        "When PBKDF2 is used, it must be supplied a random salt value with length >=128 bits",
        component,
        {
            "status": "review-required",
            "scheme": "PBKDF2",
            "note": note,
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-PWH-003
# PBKDF2 must use a sufficiently large iteration count.
#
# ECCG classification: warning
#
# Detection:
# - Simply detects PBKDF2 usage and emits the warning message.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_password_hashing_primitive(component)
    is_pbkdf2_component(component)

    note := get_note(SECTION, SUBSECTION, "27-NumberOfIterations")

    finding := build_finding(
        "ECCG-PWH-003",
        "warning",
        "When PBKDF2 is used, a sufficient large number of iterations must be provided (e.g., > 600.000 when used with SHA256 and >220.000 when used with SHA512)",
        component,
        {
            "status": "review-required",
            "scheme": "PBKDF2",
            "note": note
        }
    )
}

#
# --------------------------------------------------
# Rule ECCG-PWH-004
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
        "ECCG-PWH-004",
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
