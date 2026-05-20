package cbom.general.helpers

#
# Helper: build a standardized finding object.
#
build_finding(rule_id, severity_level, message_text, component, extra_fields) := finding_object if {

    is_valid_severity(severity_level)

    base_finding := {
        "ruleId": rule_id,
        "severity": severity_level,
        "message": message_text,
        "component": component.name,
        "bomRef": component["bom-ref"],
        "references": get_source_references(component)
    }

    finding_object := object.union(base_finding, extra_fields)
}

#
# Return the full cryptoProperties object for a component.
#
# This wrapper avoids unsafe direct access to component.cryptoProperties.
# If the field is missing, it returns an empty object so downstream helpers
# can safely continue using object.get.
#
get_crypto_properties(component) := object.get(component, "cryptoProperties", {})

#
# Return relatedCryptoMaterialProperties for a component.
#
# This object is present when cryptoProperties.assetType is
# "related-crypto-material". It contains metadata for cryptographic material
# such as private keys, public keys, secret keys, ciphertext, signatures,
# digests, or initialization vectors.
#
# If the component is not related crypto material, or if the field is missing,
# this returns an empty object.
#
get_related_crypto_material_properties(component) := object.get(
    get_crypto_properties(component),
    "relatedCryptoMaterialProperties",
    {}
)

#
# Return the CycloneDX crypto asset type for a component.
#
# Expected values include:
# - "algorithm"
# - "certificate"
# - "protocol"
# - "related-crypto-material"
#
# If the assetType field is missing, this returns "unknown".
#
get_asset_type(component) := object.get(
    get_crypto_properties(component),
    "assetType",
    "unknown"
)

#
# Return the type of related cryptographic material.
#
# This reads:
#
#   component.cryptoProperties.relatedCryptoMaterialProperties.type
#
# Expected values include:
# - "private-key"
# - "public-key"
# - "secret-key"
# - "key"
# - "ciphertext"
# - "signature"
# - "digest"
# - "initialization-vector"
#
# If the component is not related crypto material, or if the type field is
# missing, this returns "unknown".
#
get_related_crypto_material_type(component) := object.get(
    get_related_crypto_material_properties(component),
    "type",
    "unknown"
)

#
# Return the size of related cryptographic material.
#
# For RSA key material, CBOMkit may emit this as the key size in bits, for
# example:
#
#   "size": 2048
#
# If the size field is missing, this returns "unknown".
#
get_related_crypto_material_size(component) := object.get(
    get_related_crypto_material_properties(component),
    "size",
    "unknown"
)

#
# True when the component represents related cryptographic material.
#
# This identifies CBOM components where:
#
#   cryptoProperties.assetType == "related-crypto-material"
#
# These components are not algorithms themselves. They represent material
# associated with cryptographic algorithms, such as keys, signatures,
# ciphertexts, digests, or IVs.
#
is_related_crypto_material(component) if {
    get_asset_type(component) == "related-crypto-material"
}

#
# True when the component represents private key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "private-key"
#       }
#     }
#   }
#
# This is useful for flagging generated, embedded, stored, or otherwise
# exposed asymmetric private keys.
#
is_private_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type(component) == "private-key"
}

#
# True when the component represents public key material.
#
# This identifies components such as:
#
#   {
#     "cryptoProperties": {
#       "assetType": "related-crypto-material",
#       "relatedCryptoMaterialProperties": {
#         "type": "public-key"
#       }
#     }
#   }
#
# Public keys are not confidential, but they may still need policy review for
# trust, lifecycle, algorithm family, and key-size requirements.
#
is_public_key_material(component) if {
    is_related_crypto_material(component)
    get_related_crypto_material_type(component) == "public-key"
}

get_component_name(component) := object.get(component, "name", "<unknown>")

get_bom_ref(component) := object.get(component, "bom-ref", "<unknown>")

get_evidence_occurrences(component) := object.get(
    object.get(component, "evidence", {}),
    "occurrences",
    []
)

get_source_references(component) := refs if {
    refs := [
        {
            "location": object.get(occurrence, "location", "unknown"),
            "line": object.get(occurrence, "line", -1),
            "offset": object.get(occurrence, "offset", -1),
            "additionalContext": object.get(occurrence, "additionalContext", "unknown")
        } |
        occurrence := get_evidence_occurrences(component)[_]
    ]
}

get_first_source_location(component) := location if {
    occurrences := get_evidence_occurrences(component)
    count(occurrences) > 0
    location := object.get(occurrences[0], "location", "unknown")
} else := "unknown"

get_first_source_line(component) := line if {
    occurrences := get_evidence_occurrences(component)
    count(occurrences) > 0
    line := object.get(occurrences[0], "line", -1)
} else := -1

related_algorithm_for_key_material(key_component) := algorithm_component if {
    key_ref := key_component["bom-ref"]

    dependency := input.dependencies[_]
    dependency.ref == key_ref

    algorithm_ref := dependency.dependsOn[_]

    algorithm_component := input.components[_]
    algorithm_component["bom-ref"] == algorithm_ref
}

related_algorithm_name_or_unknown(key_component) := name if {
    algorithm_component := related_algorithm_for_key_material(key_component)
    name := object.get(algorithm_component, "name", "unknown")
} else := "unknown"

related_algorithm_bom_ref_or_unknown(key_component) := ref if {
    algorithm_component := related_algorithm_for_key_material(key_component)
    ref := object.get(algorithm_component, "bom-ref", "unknown")
} else := "unknown"

related_algorithm_parameter_set_or_unknown(key_component) := parameter_set if {
    algorithm_component := related_algorithm_for_key_material(key_component)

    algorithm_properties := object.get(
        object.get(algorithm_component, "cryptoProperties", {}),
        "algorithmProperties",
        {}
    )

    parameter_set := object.get(algorithm_properties, "parameterSetIdentifier", "unknown")
} else := "unknown"