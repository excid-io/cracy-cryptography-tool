package cbom.eccg.symmetric_constructions.authenticated_encryption

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.is_gcm_primitive
import data.cbom.eccg.helpers.is_ccm_primitive
import data.cbom.eccg.helpers.is_gcm_or_ccm
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.is_possible_encryption_mac_composition
import data.cbom.eccg.helpers.get_composition_match_basis
import data.cbom.eccg.helpers.get_shared_source_file_or_unknown
import data.cbom.eccg.helpers.get_shared_source_location_and_line_or_unknown
import data.cbom.eccg.helpers.get_source_references

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions"
SUBSECTION = "Symmetric-Authenticated-Encryption"

#
# ---------------------------------------------------------
# ECCG-AE-001
# GCM is an agreed authenticated-encryption scheme.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - Note 21 (DecryptionOrder)
# - Note 22 (GMAC-GCMNonce)
# - Note 23 (GMAC-GCMOptions)
# - Note 24 (GCMPlaintextLength)
# - Note 25 (GMAC-GCM-Bounds)
#
# This rule records the base ECCG classification for GCM itself.
# It does not prove that the implementation satisfies all GCM-specific
# conditions from Notes 22-25; those are handled by separate rules or,
# where the CBOM lacks enough metadata, by assessment-gap findings.
#
# TODO:
# - CBOMkit currently does not reliably detect all GCM instances
#   even when GCM is used in the source code.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_gcm_primitive(component)

    note_ids := [
        "21-DecryptionOrder",
        "22-GMAC-GCMNonce",
        "23-GMAC-GCMOptions",
        "24-GCMPlaintextLength",
        "25-GMAC-GCM-Bounds"
    ]

    notes := [
        get_note(SECTION, SUBSECTION, id)
        | id := note_ids[_]
    ]

    finding := build_finding(
        "ECCG-AE-001",
        "warning",
        "GCM is an agreed authenticated-encryption scheme, if the notes are followed accordingly.",
        component,
        {
            "status": "agreed",
            "scheme": "GCM",
            "notes": notes
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-AE-002
# CCM is an agreed authenticated-encryption scheme.
#
# ECCG classification: R (Recommended)
#
# Relevant notes:
# - Note 21 (DecryptionOrder)
#
# CCM provides AEAD security similar to GCM but does not carry
# the same parameter constraints listed in Notes 22-25.
#
# TODO:
# - CBOMkit currently does not reliably detect all CCM instances
#   even when CCM is used in the source code.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_ccm_primitive(component)

    note := get_note(SECTION, SUBSECTION, "21-DecryptionOrder")

    finding := build_finding(
        "ECCG-AE-002",
        "warning",
        "CCM is an agreed authenticated-encryption scheme, if the notes are followed.",
        component,
        {
            "status": "agreed",
            "scheme": "CCM",
            "notes": note
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-AE-003
# Decryption order requirement reminder for AEAD schemes.
#
# ECCG linkage:
# - Applies to agreed AEAD schemes such as GCM and CCM
#
# Relevant notes:
# - Note 21 (DecryptionOrder)
#
# Note 21 requires that integrity be checked before decrypted plaintext
# is exposed to consuming code. In practice, this means the implementation
# must not release plaintext before tag verification succeeds and must
# not create padding, formatting, or other decryption oracles.
#
# This property usually cannot be proven from the current CBOM alone.
# Therefore this rule is modeled as an implementation-obligation warning
# rather than a strict violation check.
# ---------------------------------------------------------
#
findings contains finding if {
    some i
    component := input.components[i]

    is_gcm_or_ccm(component)

    note := get_note(SECTION, SUBSECTION, "21-DecryptionOrder")

    finding := build_finding(
        "ECCG-AE-003",
        "warning",
        "Integrity of the ciphertext must be verified before any plaintext is released or processed, as required by Note 21-DecryptionOrder.",
        component,
        {
            "note": note,
            "status": "implementation-obligation"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-AE-004
# EAX is not currently modeled as a first-class CBOM mode.
#
# ECCG classification: R (Recommended) for EAX
#
# Relevant notes:
# - Note 21 (DecryptionOrder)
#
# ECCG lists EAX as an agreed authenticated-encryption scheme.
# However, in the current CycloneDX CBOM model, EAX does not appear
# to be represented as a first-class standard mode value in the same
# way as GCM or CCM.
#
# As a result, no direct EAX detection rule is currently implemented
# here. Detection would require either:
# - a CBOMkit-specific extension/property, or
# - a reliable name-based heuristic if EAX appears in component names.
#
# This comment is retained here intentionally so the authenticated-
# encryption policy file still documents the ECCG status of EAX and
# the current modeling limitation.
# ---------------------------------------------------------
#

#
# ---------------------------------------------------------
# ECCG-AE-005
# Encryption + MAC composition may correspond to multiple ECCG
# authenticated-encryption constructions.
#
# ECCG linkage:
# - Encrypt-then-MAC is agreed
# - MAC-then-Encrypt is legacy
# - Encrypt-and-MAC is legacy
#
# Relevant notes:
# - Note 21 (DecryptionOrder)
#
# A symmetric-encryption component and a MAC component were detected
# in a common source context. This may correspond to a composed
# authenticated-encryption construction.
#
# Because the current CBOM does not expose ordering or data-flow
# semantics, it cannot distinguish reliably between Encrypt-then-MAC,
# MAC-then-Encrypt, and Encrypt-and-MAC.
# ---------------------------------------------------------
#
findings contains finding if {
    enc_component := input.components[_]
    mac_component := input.components[_]

    enc_component["bom-ref"] != mac_component["bom-ref"]

    is_possible_encryption_mac_composition(enc_component, mac_component)

    note := get_note(SECTION, SUBSECTION, "21-DecryptionOrder")

    match_basis := get_composition_match_basis(enc_component, mac_component)
    shared_file := get_shared_source_file_or_unknown(enc_component, mac_component)
    shared_location_line := get_shared_source_location_and_line_or_unknown(enc_component, mac_component)

    finding := build_finding(
        "ECCG-AE-005",
        "medium",
        "A symmetric-encryption + MAC composition was detected. This may correspond to Encrypt-then-MAC, MAC-then-Encrypt, or Encrypt-and-MAC. Under ECCG, Encrypt-then-MAC is agreed, while MAC-then-Encrypt and Encrypt-and-MAC are legacy. Manual review is required.",
        enc_component,
        {
            "status": "composition-ambiguous",
            "notes": note,
            "relatedComponent": mac_component.name,
            "relatedBomRef": mac_component["bom-ref"],
            "relatedReferences": get_source_references(mac_component),
            "matchBasis": match_basis,
            "sharedFile": shared_file,
            "sharedLocationAndLine": shared_location_line,
            "possibleSchemes": [
                "Encrypt-then-MAC",
                "MAC-then-Encrypt",
                "Encrypt-and-MAC"
            ],
            "agreedSchemes": [
                "Encrypt-then-MAC"
            ],
            "legacySchemes": [
                "MAC-then-Encrypt",
                "Encrypt-and-MAC"
            ],
            "heuristic": true
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-AE-006
# Other authenticated-encryption schemes cannot be fully excluded.
#
# ECCG context:
# - ECCG lists several authenticated-encryption constructions,
#   including both single-component AEAD schemes and composed
#   encryption + MAC schemes.
#
# Examples:
# - GCM
# - CCM
# - EAX
# - Encrypt-then-MAC
#
# Current CBOM limitation:
# - CBOM output may not model every authenticated-encryption scheme
#   as a distinct first-class component.
# - Some schemes may appear only indirectly through lower-level
#   primitives, names, modes, or source-code patterns.
# - Composed schemes such as Encrypt-then-MAC may require ordering
#   and data-flow information that CBOM does not currently expose.
#
# As a result:
# - A missing finding does NOT prove that no authenticated-encryption
#   scheme is present.
# - A non-listed AE finding should be reviewed manually before being
#   treated as a definitive security failure.
#
# This comment is retained intentionally to document the modeling
# limitation and avoid overclaiming policy coverage.
# ---------------------------------------------------------
#