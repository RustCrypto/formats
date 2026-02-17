Object Identifiers (OID) for ML-DSA
-----------------------------------
This document lists the OIDs for
- ML-DSA-44,
- ML-DSA-65,
- ML-DSA-87,
- HashML-DSA-44 with SHA512,
- HashML-DSA-65 with SHA512, and
- HashML-DSA-87 with SHA512.

This file was manually created, as there exists no official document that is easily parsable.
The ML-DSA standard is specified in [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
The OIDs are defined in [Computer Security Objects Register (CSOR)]
(https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration),
which publishes the following ML-DSA OIDs:

nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) }

sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }

id-ml-dsa-44 OBJECT IDENTIFIER ::= { sigAlgs 17 }

id-ml-dsa-65 OBJECT IDENTIFIER ::= { sigAlgs 18 }

id-ml-dsa-87 OBJECT IDENTIFIER ::= { sigAlgs 19 }

id-hash-ml-dsa-44-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 32 }

id-hash-ml-dsa-65-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 33 }

id-hash-ml-dsa-87-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 34 }

