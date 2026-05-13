package cbom.eccg.symmetric_constructions.disk_encryption

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_note

import data.cbom.eccg.symmetric_constructions.helpers.is_disk_encryption_component
import data.cbom.eccg.symmetric_constructions.helpers.is_xts_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_cbc_essiv_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_stream_mode_for_disk

default compliant := true

compliant if count(findings) == 0

SECTION = "Symmetric-Constructions" 
SUBSECTION = "Disk-Encryption"

#
# Rule ECCG-DISK-001
# Flag disk-encryption components that are not recognized as accepted
# ECCG disk-encryption schemes.
#
# Accepted / recognized cases:
# - XTS: agreed
# - CBC-ESSIV: legacy
# - CTR/OFB: handled separately by ECCG-DISK-002 because stream modes
#   are specifically improper for disk encryption.
#
# Note:
# CBOM currently does not reliably encode disk-encryption context, so
# this rule should be treated as heuristic and may produce false positives.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_disk_encryption_component(component)
    not is_xts_scheme(component)
    not is_cbc_essiv_scheme(component)
    not is_stream_mode_for_disk(component)

    finding := build_finding(
        "ECCG-DISK-001",
        "warning",
        sprintf(
            "Disk encryption scheme '%s' is not in the accepted disk-encryption list (XTS is agreed, CBC-ESSIV is legacy). Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.",
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
# Rule ECCG-DISK-002
# Flag stream modes used in disk-encryption context.
#
# ECCG Note 9 explains that disk encryption is deterministic because
# the IV/tweak is derived from storage location. Stream modes such as
# CTR and OFB can therefore reuse keystreams when data is rewritten at
# the same location, leaking relationships between plaintexts.
#
# Note:
# This rule depends on heuristic disk-encryption detection because CBOM
# may not explicitly distinguish general encryption from disk encryption.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_disk_encryption_component(component)
    is_stream_mode_for_disk(component)

    note := get_note(SECTION, SUBSECTION, "9-DiskEncStreamMode")


    finding := build_finding(
        "ECCG-DISK-002",
        "warning",
        sprintf(
            "Scheme '%s' is a stream-mode construction and is improper for disk encryption. Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.",
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
# Rule ECCG-DISK-003
# Report required operational conditions for XTS.
#
# XTS is an agreed disk-encryption scheme, but it is only secure when
# tweak values are unique for encrypted block positions. ECCG also warns
# that address-derived tweaks require care, especially when logical
# rather than physical addresses are used.
#
# Attached notes:
# - 10-UniqueTweak
# - 11-AddressTweak
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_disk_encryption_component(component)
    is_xts_scheme(component)

    note_ids := ["10-UniqueTweak", "11-AddressTweak"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(SECTION, SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-DISK-003",
        "warning",
        "XTS requires a unique tweak value for each encrypted block position",
        component,
        {
            "notes": notes,
            "status": "agreed"
        }
    )
}

#
# Rule ECCG-DISK-004
# Flag CBC-ESSIV as legacy.
#
# CBC-ESSIV appears in the ECCG disk-encryption table as a legacy
# construction. It may still be recognized for compatibility, but it
# should not be treated as an agreed modern disk-encryption scheme.
#
# Note:
# pyca/cryptography does not expose CBC-ESSIV directly, and CBOM may not
# model it explicitly. Detection is therefore name/context-based and
# may require manual or tool-specific modeling.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_disk_encryption_component(component)
    is_cbc_essiv_scheme(component)

    finding := build_finding(
        "ECCG-DISK-004",
        "warning",
        "CBC-ESSIV is legacy in the agreed disk encryption scheme list. Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.",
        component,
        {
            "status": "legacy"
        }
    )
}

#
# Rule ECCG-DISK-005
# Report CBC-ESSIV-specific operational and security notes.
#
# CBC-ESSIV requires unique sector numbers under a given key and careful
# handling of address-derived sector numbers. ECCG also notes that CBC-
# ESSIV does not provide integrity protection and inherits CBC
# malleability concerns.
#
# Attached notes:
# - 12-UniqueSectorNumber
# - 13-AddressSectorNumber
# - 14-CBCMalleability
#
# Note:
# Because CBC-ESSIV is not directly represented by pyca/cryptography or
# reliably emitted by CBOMkit, this rule is heuristic.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_disk_encryption_component(component)
    is_cbc_essiv_scheme(component)

    note_ids := ["12-UniqueSectorNumber", "13-AddressSectorNumber", "14-CBCMalleability"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(SECTION, SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-DISK-005",
        "warning",
        "CBC-ESSIV requires each disk sector to use a unique sector number under a given key. Note that currently it's not possible to detect these schemes accurately through CBOM. There might be some false positives.",
        component,
        {
            "notes": notes,
            "status": "legacy"
        }
    )
}