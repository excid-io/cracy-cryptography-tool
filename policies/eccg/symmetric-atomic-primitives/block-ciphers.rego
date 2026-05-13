package cbom.eccg.symmetric_atomic_primitives.block_ciphers

import data.cbom.eccg.helpers.is_block_cipher_primitive
import data.cbom.eccg.helpers.get_mode_or_unknown
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown
import data.cbom.eccg.helpers.get_note
import data.cbom.eccg.helpers.build_finding

import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_aes_component
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_3des_component
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_agreed_block_cipher_component
import data.cbom.eccg.symmetric_atomic_primitives.helpers.is_allowed_aes_key_size

#
# Overall result:
# - compliant = true  => no findings were produced
# - compliant = false => at least one finding exists
#
default compliant := true

compliant if count(findings) == 0

NOTE_SECTION := "Symmetric-Atomic-Primitives"
NOTE_SUBSECTION := "Block-Ciphers"

#
# findings is a computed collection of policy violations / warnings.
# Each rule below can add one finding object to this collection.
#

#
# Rule ECCG-BLOCK-001
# Flag any block cipher that is not AES or 3DES.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_block_cipher_primitive(component)
    not is_agreed_block_cipher_component(component)

    finding := build_finding(
        "ECCG-BLOCK-001",
        "critical",
        sprintf("Block cipher '%s' is not in the agreed block cipher list. That does mean that your code is unsafe, but should probably be marked as non compliant.", [component.name]),
        component,
        {
            "primitive": get_primitive_or_unknown(component),
            #TODO these are not the key bits
            "keyBits": get_parameter_set_identifier_to_number_or_unknown(component),
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-BLOCK-002
# AES is only agreed with key sizes 128, 192, or 256 bits.
# TODO: this rule won't ever fire correctly because we can't correctly detect the keySize through the CBOM kit
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_aes_component(component)
    not is_allowed_aes_key_size(component)

    finding := build_finding(
        "ECCG-BLOCK-002",
        "high",
        sprintf(
            "AES uses a non-agreed key size: %v bits. Allowed sizes are 128, 192, or 256 bits",
            [get_parameter_set_identifier_to_number_or_unknown(component)]
        ),
        component,
        {
            "allowedKeySizes": [128, 192, 256],
            "actualKeyBits": get_parameter_set_identifier_to_number_or_unknown(component),
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-BLOCK-003
# Triple-DES / 3DES must use a 168-bit key size according to the rule set.
# TODO: this rule won't ever fire correctly because we can't correctly detect the keySize through the CBOM kit
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_3des_component(component)
    #TODO these are not the key bits
    get_parameter_set_identifier_to_number_or_unknown(component) != 168

    finding := build_finding(
        "ECCG-BLOCK-003",
        "high",
        sprintf(
            "3DES uses a non-agreed key size: %v bits. Required size is 168 bits",
            #TODO these are not the key bits
            [get_parameter_set_identifier_to_number_or_unknown(component)]
        ),
        component,
        {
            "requiredKeyBits": 168,
            "actualKeyBits": get_parameter_set_identifier_to_number_or_unknown(component),
            "mode": object.get(component.cryptoProperties.algorithmProperties, "mode", "")
        }
    )
}

#
# Rule ECCG-BLOCK-004
# Even when 3DES has the expected size, it is still legacy-only.
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_3des_component(component)


    note_ids := ["2-SmallBlockSize", "3-QuantumThreat"]
    notes := [ { "noteId": id, "noteTitle": note.title, "noteText": note.text } | 
        id := note_ids[_] 
        note := get_note(NOTE_SECTION, NOTE_SUBSECTION, id) ]

    finding := build_finding(
        "ECCG-BLOCK-004",
        "high",
        "3DES will become legacy-only in 2027 and carries a small-block-size limitation (64-bit block) and a quantum-threat note",
        component,
        {
            "notes": notes,
            "mode": get_mode_or_unknown(component)
        }
    )
}

#
# Rule ECCG-BLOCK-005
# In quantum-sensitive contexts, agreed block ciphers below 192 bits are discouraged.
# TODO: this won't ever fire correctly due to parameterSetIdentifier
#
findings contains finding if {
    some component_index
    component := input.components[component_index]

    is_block_cipher_primitive(component)
    is_agreed_block_cipher_component(component)
    get_parameter_set_identifier_to_number_or_unknown(component) < 192

    note_id :=  "3-QuantumThreat"

    note := get_note(NOTE_SECTION, NOTE_SUBSECTION, note_id)

    finding := build_finding(
        "ECCG-BLOCK-005",
        "medium",
        sprintf(
            "Cipher '%s' uses %v-bit keying, which is below 192 bits and should be avoided where resistance to quantum attacks is required",
            [component.name, get_parameter_set_identifier_to_number_or_unknown(component)]
        ),
        component,
        {
            "notes": note,
            "minimumRecommendedBitsForQuantumSensitiveContext": 192,
            "actualKeyBits":get_parameter_set_identifier_to_number_or_unknown(component),
            "mode": get_mode_or_unknown(component)
        }
    )
}
