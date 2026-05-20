
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