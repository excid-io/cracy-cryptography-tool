package cbom.eccg.symmetric_atomic_primitives.helpers

import data.cbom.eccg.helpers.get_parameter_set_identifier_to_number_or_unknown

#
# Helper: identify AES-family components by name.
#
is_aes_component(component) if {
    startswith(upper(component.name), "AES")
}

#
# Helper: identify Triple-DES / 3DES by name.
#
is_3des_component(component) if {
    startswith(upper(component.name), "3DES")
} else if {
    startswith(upper(component.name), "TRIPLE-DES")
}

#
# Helpers: identify SHA functions.
#
is_sha224(component) if {
    component.name == "SHA224"
}

is_sha256(component) if {
    component.name == "SHA256"
}

is_sha384(component) if {
    component.name == "SHA384"
}

is_sha512(component) if {
    component.name == "SHA512"
}

is_sha512_224(component) if {
    component.name == "SHA512/224"
}

is_sha512_256(component) if {
    component.name == "SHA512/256"
}

is_sha3_256(component) if {
    component.name == "SHA3-256"
}

is_sha3_384(component) if {
    component.name == "SHA3-384"
}

is_sha3_512(component) if {
    component.name == "SHA3-512"
}

is_sha1(component) if {
    component.name == "SHA1"
}

is_legacy_hash_component(component) if {
    is_sha224(component)
} else if {
    is_sha512_224(component)
} else if {
    is_sha1(component)
}

is_agreed_hash_component(component) if {
    is_sha256(component)
} else if {
    is_sha384(component)
} else if {
    is_sha512(component)
} else if {
    is_sha512_256(component)
} else if {
    is_sha3_256(component)
} else if {
    is_sha3_384(component)
} else if {
    is_sha3_512(component)
}

is_block_cipher_component(component) if {
   is_3des_component(component) 
}

is_block_cipher_component(component) if {
   is_aes_component(component) 
}

#
# Helper: allowed AES key sizes are 128, 192, or 256 bits.
# TODO: parameterSetIdentifier does not seem to be the actual key size used
#
is_allowed_aes_key_size(component) if {
    key_size_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    key_size_bits == 128
    is_aes_component(component)
} 

is_allowed_aes_key_size(component) if {
    key_size_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    key_size_bits == 192
    is_aes_component(component)
}

is_allowed_aes_key_size(component) if {
    key_size_bits := get_parameter_set_identifier_to_number_or_unknown(component)
    key_size_bits == 256
    is_aes_component(component)
}

is_agreed_block_cipher_component(component) if {
    is_aes_component(component)
}

is_agreed_block_cipher_component(component) if {
    is_3des_component(component)
}


