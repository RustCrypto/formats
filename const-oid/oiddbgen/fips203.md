Object Identifiers (OID) for ML-KEM
-----------------------------------
This document lists the OIDs for
- ML-KEM-512,
- ML-KEM-768, and
- ML-KEM-1024.

This file was manually created, as there exists no official document that is easily parsable.
The ML-KEM standard is specified in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
The OIDs are defined in [Computer Security Objects Register (CSOR)]
(https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration),
which publishes the following ML-KEM OIDs:

nistAlgorithms OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4) }

kems OBJECT IDENTIFIER ::= { nistAlgorithms 4 }

id-alg-ml-kem-512 OBJECT IDENTIFIER ::= { kems 1 }

id-alg-ml-kem-768 OBJECT IDENTIFIER ::= { kems 2 }

id-alg-ml-kem-1024 OBJECT IDENTIFIER ::= { kems 3 }
