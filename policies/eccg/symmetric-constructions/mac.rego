package cbom.eccg.symmetric_constructions.mac

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.is_mac_primitive
import data.cbom.eccg.helpers.legacy_marker_status
import data.cbom.eccg.helpers.evaluation_year
import data.cbom.eccg.helpers.legacy_status_severity
import data.cbom.eccg.helpers.legacy_status_message

import data.cbom.eccg.symmetric_constructions.helpers.is_cmac_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_cbc_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_hmac_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_hmac_sha1_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_kmac128_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_kmac256_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_kmac_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_gmac_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_possible_gmac_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_unlisted_mac_scheme

default compliant := true

compliant if count(findings) == 0

SECTION := "Symmetric-Constructions"
SUBSECTION := "Message-Authentication-Codes"

#
# Rule ECCG-MAC-000
# MAC scheme not listed by ECCG.
#
findings contains finding if {
    component := input.components[_]

    is_unlisted_mac_scheme(component)

    finding := build_finding(
        "ECCG-MAC-000",
        "high",
        sprintf("MAC scheme '%s' is not listed in the ECCG agreed or legacy MAC tables.", [component.name]),
        component,
        {
            "status": "not-listed"
        }
    )
}

#
# Rule ECCG-MAC-001
# CMAC is agreed.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_cmac_scheme(component)

    finding := build_finding(
        "ECCG-MAC-001",
        "info",
        "CMAC is an agreed MAC scheme.",
        component,
        {
            "status": "agreed"
        }
    )
}

#
# Rule ECCG-MAC-002
# CBC may correspond to manually implemented CBC-MAC.
#
findings contains finding if {
    component := input.components[_]

    is_cbc_scheme(component)

    note := get_note(SECTION, SUBSECTION, "17-FixedInputLength")

    finding := build_finding(
        "ECCG-MAC-002",
        "warning",
        sprintf(
            "CBC-based construction '%s' may correspond to manually implemented CBC-MAC. CBC-MAC is agreed only when all inputs computed under the same key have identical size.",
            [component.name]
        ),
        component,
        {
            "status": "heuristic",
            "notes": note,
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-HMAC-001
# HMAC detected, but real MAC key size is not available in current CBOM.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_hmac_scheme(component)
    not is_hmac_sha1_scheme(component)

    note := get_note(SECTION, SUBSECTION, "19-QuantumThreat")

    finding := build_finding(
        "ECCG-HMAC-001",
        "warning",
        "HMAC is listed by ECCG, but the runtime MAC key size is not available in the current CBOM; agreement threshold cannot be fully assessed.",
        component,
        {
            "status": "undetermined",
            "requiredAgreedKeySizeBits": 125,
            "legacyThresholdKeySizeBits": 100,
            "detectedParameterSetIdentifier": get_parameter_set_identifier_to_number_or_unknown(component),
            "notes": note
        }
    )
}

#
# Rule ECCG-HMAC-002
# HMAC-SHA1 is legacy.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_hmac_sha1_scheme(component)

    note := get_note(SECTION, SUBSECTION, "18-HMAC-SHA-1")

    legacy_marker := "L[2030]"
    status := legacy_marker_status(legacy_marker)
    severity := legacy_status_severity(status)
    message := legacy_status_message("HMAC-SHA1", legacy_marker, status)

    finding := build_finding(
        "ECCG-HMAC-002",
        severity,
        message,
        component,
        {
            "status": status,
            "legacyMarker": legacy_marker,
            "legacyUntilYear": 2030,
            "evaluationYear": evaluation_year,
            "notes": note,
            "requiredMinimumKeySizeBits": 100,
            "detectedParameterSetIdentifier": get_parameter_set_identifier_to_number_or_unknown(component)
        }
    )
}

#
# Rule ECCG-KMAC-001
# KMAC128 detected, but real key size is not available in current CBOM.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_kmac128_scheme(component)

    note := get_note(SECTION, SUBSECTION, "19-QuantumThreat")

    finding := build_finding(
        "ECCG-KMAC-001",
        "warning",
        "KMAC128 is listed by ECCG, but the runtime MAC key size is not available in the current CBOM; agreement threshold cannot be fully assessed.",
        component,
        {
            "status": "undetermined",
            "requiredAgreedKeySizeBits": 125,
            "detectedParameterSetIdentifier": get_parameter_set_identifier_to_number_or_unknown(component),
            "notes": note
        }
    )
}

#
# Rule ECCG-KMAC-002
# KMAC256 detected, but real key size is not available in current CBOM.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_kmac256_scheme(component)

    note := get_note(SECTION, SUBSECTION, "19-QuantumThreat")

    finding := build_finding(
        "ECCG-KMAC-002",
        "warning",
        "KMAC256 is listed by ECCG, but the runtime MAC key size is not available in the current CBOM; agreement threshold cannot be fully assessed.",
        component,
        {
            "status": "undetermined",
            "requiredAgreedKeySizeBits": 250,
            "detectedParameterSetIdentifier": get_parameter_set_identifier_to_number_or_unknown(component),
            "notes": note
        }
    )
}

#
# Rule ECCG-KMAC-003
# Generic fallback for KMAC.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_kmac_scheme(component)
    not is_kmac128_scheme(component)
    not is_kmac256_scheme(component)

    finding := build_finding(
        "ECCG-KMAC-003",
        "warning",
        "KMAC was detected, but the variant could not be determined as KMAC128 or KMAC256.",
        component,
        {
            "status": "undetermined"
        }
    )
}

#
# Rule ECCG-GMAC-001
# GMAC is agreed, subject to GCM/GMAC constraints.
# TODO: GMAC is not detected by CBOM kit
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)
    is_gmac_scheme(component)

    note_ids := [
        "22-GMAC-GCMNonce",
        "23-GMAC-GCMOptions",
        "25-GMAC-GCM-Bounds"
    ]

    notes := [
        {"noteId": id, "noteTitle": note.title, "noteText": note.text} |
        id := note_ids[_]
        note := get_note(SECTION, SUBSECTION, id)
    ]

    finding := build_finding(
        "ECCG-GMAC-001",
        "info",
        "GMAC is an agreed universal-hash-function-based MAC scheme, subject to GCM/GMAC operational constraints.",
        component,
        {
            "status": "agreed",
            "notes": notes
        }
    )
}

#
# Rule ECCG-GMAC-002
# GCM may correspond to GMAC-style authentication-only usage.
#
findings contains finding if {
    component := input.components[_]

    is_possible_gmac_scheme(component)

    note_ids := [
        "22-GMAC-GCMNonce",
        "23-GMAC-GCMOptions",
        "25-GMAC-GCM-Bounds"
    ]

    notes := [
        {"noteId": id, "noteTitle": note.title, "noteText": note.text} |
        id := note_ids[_]
        note := get_note(SECTION, SUBSECTION, id)
    ]

    finding := build_finding(
        "ECCG-GMAC-002",
        "warning",
        sprintf(
            "GCM-based construction '%s' may correspond to GMAC-style authentication-only usage. This cannot be fully determined from CBOM alone.",
            [component.name]
        ),
        component,
        {
            "status": "possible-gmac",
            "mode": get_mode_or_unknown(component),
            "notes": notes
        }
    )
}

#
# Rule ECCG-MAC-003
# General MAC truncation notes.
#
findings contains finding if {
    component := input.components[_]

    is_mac_primitive(component)

    note_ids := [
        "15-MACTruncation96",
        "16-MACTruncation64"
    ]

    notes := [
        {"noteId": id, "noteTitle": note.title, "noteText": note.text} |
        id := note_ids[_]
        note := get_note(SECTION, SUBSECTION, id)
    ]

    finding := build_finding(
        "ECCG-MAC-003",
        "warning",
        "MAC truncation requirements may apply. The current CBOM does not expose final MAC/tag length, so truncation compliance cannot be fully assessed.",
        component,
        {
            "status": "undetermined",
            "notes": notes
        }
    )
}