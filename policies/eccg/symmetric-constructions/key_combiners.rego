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
# CatKDF is an agreed key combiner.
#
# ECCG classification: R
#
# Detection:
# - Explicit combiner primitive named CatKDF, or
# - KDF primitive named ConcatKDFHash / ConcatKDFHMAC /
#   ConcatenationKDF.
#
# CBOMkit limitation:
# - CBOMkit may detect only the underlying KDF, not the semantic
#   CatKDF key-combiner construction.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_catkdf_scheme(component)

    finding := build_finding(
        "ECCG-KC-001",
        "info",
        "CatKDF / Concatenate-then-KDF is an agreed key combiner mechanism. Detection may be based on ConcatKDFHash or ConcatKDFHMAC because CBOMkit may not model CatKDF as a first-class combiner.",
        component,
        {
            "status": "agreed",
            "scheme": "CatKDF",
            "primitive": get_primitive_or_unknown(component),
            "combiner": is_explicit_combiner(component)
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KC-002
# CasKDF is an agreed key combiner.
#
# ECCG classification: R
#
# Detection:
# - Explicit combiner primitive named CasKDF / CascadeKDF.
#
# CBOMkit limitation:
# - CBOMkit is unlikely to detect CasKDF directly.
# - Cascade behavior usually requires data-flow/order information
#   that CBOM does not expose.
# ---------------------------------------------------------
#
findings contains finding if {
    component := input.components[_]

    is_caskdf_scheme(component)

    finding := build_finding(
        "ECCG-KC-002",
        "info",
        "CasKDF / Cascade-KDF is an agreed key combiner mechanism. Direct detection is unlikely unless the CBOM explicitly names the construction.",
        component,
        {
            "status": "agreed",
            "scheme": "CasKDF",
            "primitive": get_primitive_or_unknown(component),
            "combiner": is_explicit_combiner(component)
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KC-003
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
        "ECCG-KC-003",
        "info",
        "Multiple KDF components were detected in a shared source context. This may correspond to a CasKDF / Cascade-KDF key combiner, but CBOM does not expose ordering or data-flow semantics. Manual review is required.",
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
# ECCG-KC-004
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
        "ECCG-KC-004",
        "critical",
        sprintf(
            "Key combiner scheme '%s' is not listed in the ECCG agreed key combiner table.",
            [component.name]
        ),
        component,
        {
            "status": "not-listed",
            "primitive": "combiner"
        }
    )
}

#
# ---------------------------------------------------------
# ECCG-KC-005
# Key combiner detection coverage limitation.
#
# CatKDF and CasKDF are high-level constructions over KDFs and
# key-establishment outputs. CBOMkit may only emit lower-level KDF
# components such as ConcatKDFHash or ConcatKDFHMAC, or may not emit
# a combiner primitive at all.
#
# Therefore:
# - absence of a key-combiner finding does not prove absence of
#   CatKDF or CasKDF;
# - possible cascade findings are heuristic only;
# - precise validation may require source-code/data-flow analysis.
# ---------------------------------------------------------
#