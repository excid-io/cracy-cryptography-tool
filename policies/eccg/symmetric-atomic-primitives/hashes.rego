package cbom.eccg.symmetric_atomic_primitives.hash_primitives

import data.cbom.eccg.helpers.is_hash_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding

import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_sha224
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_sha512_224
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_legacy_hash_component
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_agreed_hash_component

default compliant := true

compliant if count(findings) == 0

NOTE_SECTION := "Symmetric-Atomic-Primitives"
NOTE_SUBSECTION := "Hash-Functions"

#
# Rule ECCG-HASH-001
# SHA-224 is legacy-only (L[2025]).
# TODO: hashBits won't ever be correct because get_parameter_set_identifier_to_number_or_unknown
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_hash_primitive(component)
    is_sha224(component)

    finding := build_finding(
        "ECCG-HASH-001",
        "critical",
        sprintf("Hash function '%s' is legacy-only (L[2025]) and is not an agreed hash function", [component.name]),
        component,
        {
            "status": "legacy",
            "hashBits": get_parameter_set_identifier_to_number_or_unknown(component),
            "legacyUntil": "2025"
        }
    )
}

#
# Rule ECCG-HASH-002
# SHA-512/224 is legacy-only (L[2025]).
# TODO: hashBits won't ever be correct because get_parameter_set_identifier_to_number_or_unknown
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_hash_primitive(component)
    is_sha512_224(component)

    finding := build_finding(
        "ECCG-HASH-002",
        "critical",
        sprintf("Hash function '%s' is legacy-only (L[2025]) and is not an agreed hash function", [component.name]),
        component,
        {
            "status": "legacy",
            "hashBits": get_parameter_set_identifier_to_number_or_unknown(component),
            "legacyUntil": "2025"
        }
    )
}

#
# Rule ECCG-HASH-003
# Any hash not in the agreed list should be flagged.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_hash_primitive(component)
    not is_legacy_hash_component(component)
    not is_agreed_hash_component(component)

    finding := build_finding(
        "ECCG-HASH-003",
        "warning",
        sprintf("Hash function '%s' is not in the agreed hash function list. This does not mean that your code is unsafe, but this should probably be flagged as non compliant.", [component.name]),
        component,
        {
            "hashBits": get_parameter_set_identifier_to_number_or_unknown(component)
        }
    )
}

#
# Rule ECCG-HASH-004
# In quantum-sensitive contexts, hash output below 384 bits should be avoided.
# TODO: this won't ever fire correctly due to the parameterSetIdentifier not being the hashSize
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_hash_primitive(component)
    get_parameter_set_identifier_to_number_or_unknown(component) < 384

    note := get_note(NOTE_SECTION, NOTE_SUBSECTION, "4-QuantumThreat")

    finding := build_finding(
        "ECCG-HASH-004",
        "warning",
        sprintf(
            "Hash function '%s' has output length %v bits, which is below the recommended 384 bits for quantum-sensitive contexts",
            [component.name, get_parameter_set_identifier_to_number_or_unknown(component)]
        ),
        component,
        {
            "notes": note,
            "minimumRecommendedHashBits": 384,
            "actualHashBits": get_parameter_set_identifier_to_number_or_unknown(component)
        }
    )
}