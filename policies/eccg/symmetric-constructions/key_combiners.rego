package cbom.eccg.symmetric_constructions.key_combiners

import data.cbom.eccg.helpers.build_finding
import data.cbom.eccg.helpers.get_primitive_or_unknown
import data.cbom.eccg.helpers.is_kdf_primitive
import data.cbom.eccg.helpers.is_combiner_primitive
import data.cbom.eccg.helpers.is_explicit_combiner
import data.cbom.eccg.helpers.same_source_file
import data.cbom.eccg.helpers.shares_evidence_location_and_line
import data.cbom.eccg.helpers.get_composition_match_basis
import data.cbom.eccg.helpers.get_shared_source_file_or_unknown
import data.cbom.eccg.helpers.get_shared_source_location_and_line_or_unknown
import data.cbom.eccg.helpers.get_source_references

import data.cbom.eccg.symmetric_constructions.helpers.is_catkdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_caskdf_scheme
import data.cbom.eccg.symmetric_constructions.helpers.is_possible_caskdf_composition
import data.cbom.eccg.symmetric_constructions.helpers.is_agreed_key_combiner_scheme



default compliant := true

compliant if count(findings) == 0

SECTION := "Symmetric-Constructions"
SUBSECTION := "Key-Combiners"


#
# ---------------------------------------------------------
# ECCG-KC-001
# CatKDF and CasKDF are the only recommended key combiner schemes.
#
# ECCG classification:
# - info when CatKDF or CasKDF is detected
# - warning when a KDF/combiner-like construction is detected but is not
#   an agreed key combiner scheme
#
# Detection:
# - CatKDF:
#   - explicit combiner primitive named CatKDF, or
#   - KDF primitive named ConcatKDFHash / ConcatKDFHMAC /
#     ConcatenationKDF.
#
# - CasKDF:
#   - explicit combiner primitive named CasKDF / CascadeKDF.
#
# - Non-agreed:
#   - KDF primitive or combiner primitive that is not CatKDF or CasKDF.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_kdf_primitive(component) 
    not is_agreed_key_combiner_scheme(component)

    finding := build_finding(
        "ECCG-KC-001",
        "warning",
        "CatKDF and CasKDF are the only recommended key combiner schemes. Note that this might be a false positive, due to the inability to differentiate between KDFs and Key Combiner in the CBOM.",
        component,
        {
            "status": "notAgreed",
            "scheme": object.get(component, "name", "unknown"),
            "notes": [
                "This KDF component is not detected as CatKDF or CasKDF. Review whether it is being used as a key combiner."
            ]
        }
    )
}


#
# ---------------------------------------------------------
# ECCG-KC-002
# Possible CasKDF-style cascade detected.
#
# A pair of KDF components appears in a common source context.
# This may correspond to a cascade-style key combiner.
#
# Because CBOM does not expose ordering/data-flow semantics,
# this cannot prove CasKDF. Manual review is required.
# ---------------------------------------------------------
#
findings contains finding if {
    kdf_component_a := input.components[_]
    kdf_component_b := input.components[_]

    is_possible_caskdf_composition(kdf_component_a, kdf_component_b)

    match_basis := get_composition_match_basis(kdf_component_a, kdf_component_b)
    shared_file := get_shared_source_file_or_unknown(kdf_component_a, kdf_component_b)
    shared_location_line := get_shared_source_location_and_line_or_unknown(kdf_component_a, kdf_component_b)

    finding := build_finding(
        "ECCG-KC-002",
        "info",
        "Multiple KDF components were detected in a shared source context. This could be a Key Combiner Scheme. Note that the only acceptable Key Combiner schemes are CatKDF and CasKDF. Manual review is required.",
        kdf_component_a,
        {
            "status": "possible-caskdf",
            "scheme": "CasKDF",
            "relatedComponent": kdf_component_b.name,
            "relatedBomRef": kdf_component_b["bom-ref"],
            "relatedReferences": get_source_references(kdf_component_b),
            "matchBasis": match_basis,
            "sharedFile": shared_file,
            "sharedLocationAndLine": shared_location_line,
            "heuristic": true
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KC-001*
# Non-agreed key combiner scheme.
#
# ECCG only lists CatKDF and CasKDF as agreed key combiners.
# If CBOM explicitly emits primitive = "combiner" but the scheme is
# not CatKDF or CasKDF, flag it for review.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_combiner_primitive(component)
    not is_agreed_key_combiner_scheme(component)

    finding := build_finding(
        "ECCG-KC-001*",
        "critical",
        sprintf(
            "Key combiner scheme '%s' is not listed in the ECCG agreed key combiner table. The only agreed ones are CatKDF and CasKDF.",
            [component.name]
        ),
        component,
        {
            "status": "not-listed",
            "primitive": "combiner"
        }
    )
}
