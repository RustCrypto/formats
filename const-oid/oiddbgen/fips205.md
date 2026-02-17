Object Identifiers (OID) for SLH-DSA
------------------------------------
This document lists the OIDs for
- SLH-DSA-SHA2-128s,
- SLH-DSA-SHA2-128f,
- SLH-DSA-SHA2-192s,
- SLH-DSA-SHA2-192f,
- SLH-DSA-SHA2-256s,
- SLH-DSA-SHA2-256f,
- SLH-DSA-SHAKE-128s,
- SLH-DSA-SHAKE-128f,
- SLH-DSA-SHAKE-192s,
- SLH-DSA-SHAKE-192f,
- SLH-DSA-SHAKE-256s,
- SLH-DSA-SHAKE-256f,
- HashSLH-DSA-SHA2-128s-with-sha256,
- HashSLH-DSA-SHA2-128f-with-sha256,
- HashSLH-DSA-SHA2-192s-with-sha512,
- HashSLH-DSA-SHA2-192f-with-sha512,
- HashSLH-DSA-SHA2-256s-with-sha512,
- HashSLH-DSA-SHA2-256f-with-sha512,
- HashSLH-DSA-SHAKE-128s-with-shake128,
- HashSLH-DSA-SHAKE-128f-with-shake128,
- HashSLH-DSA-SHAKE-192s-with-shake256,
- HashSLH-DSA-SHAKE-192f-with-shake256,
- HashSLH-DSA-SHAKE-256s-with-shake256, and
- HashSLH-DSA-SHAKE-256f-with-shake256.

This file was manually created, as there exists no official document that is easily parsable.
The SLH-DSA standard is specified in [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).
The OIDs are defined in [Computer Security Objects Register (CSOR)]
(https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration),
which publishes the following SLH-DSA OIDs:

nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) }

sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }

id-slh-dsa-sha2-128s OBJECT IDENTIFIER ::= { sigAlgs 20 }

id-slh-dsa-sha2-128f OBJECT IDENTIFIER ::= { sigAlgs 21 }

id-slh-dsa-sha2-192s OBJECT IDENTIFIER ::= { sigAlgs 22 }

id-slh-dsa-sha2-192f OBJECT IDENTIFIER ::= { sigAlgs 23 }

id-slh-dsa-sha2-256s OBJECT IDENTIFIER ::= { sigAlgs 24 }

id-slh-dsa-sha2-256f OBJECT IDENTIFIER ::= { sigAlgs 25 }

id-slh-dsa-shake-128s OBJECT IDENTIFIER ::= { sigAlgs 26 }

id-slh-dsa-shake-128f OBJECT IDENTIFIER ::= { sigAlgs 27 }

id-slh-dsa-shake-192s OBJECT IDENTIFIER ::= { sigAlgs 28 }

id-slh-dsa-shake-192f OBJECT IDENTIFIER ::= { sigAlgs 29 }

id-slh-dsa-shake-256s OBJECT IDENTIFIER ::= { sigAlgs 30 }

id-slh-dsa-shake-256f OBJECT IDENTIFIER ::= { sigAlgs 31 }

id-hash-slh-dsa-sha2-128s-with-sha256 OBJECT IDENTIFIER ::= { sigAlgs 35 }

id-hash-slh-dsa-sha2-128f-with-sha256 OBJECT IDENTIFIER ::= { sigAlgs 36 }

id-hash-slh-dsa-sha2-192s-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 37 }

id-hash-slh-dsa-sha2-192f-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 38 }

id-hash-slh-dsa-sha2-256s-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 39 }

id-hash-slh-dsa-sha2-256f-with-sha512 OBJECT IDENTIFIER ::= { sigAlgs 40 }

id-hash-slh-dsa-shake-128s-with-shake128 OBJECT IDENTIFIER ::= { sigAlgs 41 }

id-hash-slh-dsa-shake-128f-with-shake128 OBJECT IDENTIFIER ::= { sigAlgs 42 }

id-hash-slh-dsa-shake-192s-with-shake256 OBJECT IDENTIFIER ::= { sigAlgs 43 }

id-hash-slh-dsa-shake-192f-with-shake256 OBJECT IDENTIFIER ::= { sigAlgs 44 }

id-hash-slh-dsa-shake-256s-with-shake256  OBJECT IDENTIFIER ::= { sigAlgs 45 }

id-hash-slh-dsa-shake-256f-with-shake256 OBJECT IDENTIFIER ::= { sigAlgs 46 }
