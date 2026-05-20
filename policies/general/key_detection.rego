package cbom.general.key_detection

import data.cbom.helpers.build_finding
import data.cbom.helpers.is_private_key_material
import data.cbom.helpers.is_public_key_material

#
# ---------------------------------------------------------
# ECCG-RSA-KEY-001
# Private key material detected.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_private_key_material(component)

    finding := build_finding(
        "ECCG-RSA-KEY-001",
        "high",
        sprintf(
            "Private key material '%s' was detected in the CBOM. Review whether this key is generated, embedded, stored, or otherwise exposed in the source context.",
            [get_component_name(component)]
        ),
        component,
        {
            "assetType": get_asset_type(component),
            "materialType": get_related_crypto_material_type(component),
            "size": get_related_crypto_material_size(component),
            "relatedAlgorithm": related_algorithm_name_or_unknown(component),
            "relatedAlgorithmBomRef": related_algorithm_bom_ref_or_unknown(component),
            "relatedAlgorithmParameterSetIdentifier": related_algorithm_parameter_set_or_unknown(component),
            "bomRef": get_bom_ref(component),
            "sourceReferences": get_source_references(component),
            "sourceLocation": get_first_source_location(component),
            "sourceLine": get_first_source_line(component)
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-RSA-KEY-002
# Public key material detected.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_public_key_material(component)

    finding := build_finding(
        "ECCG-RSA-KEY-002",
        "info",
        sprintf(
            "Public key material '%s' was detected in the CBOM. Public keys are not confidential, but should still be reviewed for lifecycle, trust, and algorithm-size policy.",
            [get_component_name(component)]
        ),
        component,
        {
            "assetType": get_asset_type(component),
            "materialType": get_related_crypto_material_type(component),
            "size": get_related_crypto_material_size(component),
            "relatedAlgorithm": related_algorithm_name_or_unknown(component),
            "relatedAlgorithmBomRef": related_algorithm_bom_ref_or_unknown(component),
            "relatedAlgorithmParameterSetIdentifier": related_algorithm_parameter_set_or_unknown(component),
            "bomRef": get_bom_ref(component),
            "sourceReferences": get_source_references(component),
            "sourceLocation": get_first_source_location(component),
            "sourceLine": get_first_source_line(component)
        }
    )
}
