
# Symmetric Atomic Primitives 

## ECCG-BLOCK-001: Non-Agreed Block Cipher

ECCG-BLOCK-001 detects block cipher primitives that are not in the agreed ECCG block cipher list. The agreed list currently includes AES and 3DES. Any detected block cipher outside that list is reported as non-compliant.

For example, the following pyca/cryptography code can produce a CBOM entry for Blowfish:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"K" * 16
iv = b"I" * 8

cipher = Cipher(
    algorithms.Blowfish(key),
    modes.CBC(iv),
)
```

## ECCG-BLOCK-003: Non-Agreed 3DES Key Size

ECCG-BLOCK-003 detects 3DES components whose detected key size does not match the expected ECCG value:

```
requiredKeyBits = 168
```

For example, the following pyca/cryptography code can produce a 3DES CBOM entry:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b"1234567890ABCDEF"
iv = b"12345678"

cipher = Cipher(
    algorithms.TripleDES(key),
    modes.CBC(iv),
)
```

This can produce a finding such as:

```
Rule: ECCG-BLOCK-003
```

3DES uses a non-agreed key size: 64 bits. Required size is 168 bits

In practice, this rule is sensitive to how CBOMkit populates parameterSetIdentifier. For block ciphers, the value may reflect the block size, mode parameter, or another algorithm identifier rather than the actual key size. In the example finding, 3DES is reported with 64 bits, which likely reflects the 64-bit block size rather than the effective 3DES keying material. Because of that, key-size findings for block ciphers should be treated as useful signals but not always definitive. Manual review may be required to confirm the actual key length used in source code.

# Asymmetric Atomic Primitives 

## ECCG-RSA-002: Legacy RSA Modulus Size

ECCG-RSA-002 detects RSA primitives whose modulus size is in the ECCG legacy range:

```
1900 <= modulusBits < 3000
```

In practice, this means RSA-2048 is flagged as legacy. RSA security depends heavily on the size of the modulus n. Under this rule set, RSA keys below 3000 bits are treated as legacy. A 2048-bit RSA key is still commonly encountered, but it does not meet the recommended ECCG modulus-size threshold. The rule reports this as a critical finding because the detected RSA primitive is classified as Legacy[2025].

The ECCG rule also includes a condition on the RSA public exponent:

```
log2(e) > 16
```

However, CycloneDX does not expose the RSA public exponent in the CBOM data used by this rule. Because of that, the policy can only evaluate the modulus size. The finding therefore marks the exponent check as:

```
not_verifiable
```