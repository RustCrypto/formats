Object Identifiers (OID) for TCG TPM
------------------------------------

This document lists the OIDs for TPM registered by the Trusted Computing Group.

This file was manually created, as there exists no official document that is easily parsable.

tcgOrganization OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) international-organizations(23) 133 }


tcg-tcpaSpecVersion OBJECT IDENTIFIER ::= { tcgOrganization 1 }

tcg-sv-tpm12 OBJECT IDENTIFIER ::= { tcg-tcpaSpecVersion 0 }
tcg-sv-tpm20 OBJECT IDENTIFIER ::= { tcg-tcpaSpecVersion 2 }


tcg-attribute OBJECT IDENTIFIER ::= { tcgOrganization 2 }

tcg-at-tpmManufacturer          OBJECT IDENTIFIER ::= { tcg-attribute 1 }
tcg-at-tpmModel                 OBJECT IDENTIFIER ::= { tcg-attribute 2 }
tcg-at-tpmVersion               OBJECT IDENTIFIER ::= { tcg-attribute 3 }
tcg-at-platformManufacturer     OBJECT IDENTIFIER ::= { tcg-attribute 4 }
tcg-at-platformModel            OBJECT IDENTIFIER ::= { tcg-attribute 5 }
tcg-at-platformVersion          OBJECT IDENTIFIER ::= { tcg-attribute 6 }
tcg-at-securityQualities        OBJECT IDENTIFIER ::= { tcg-attribute 10 }
tcg-at-tpmProtectionProfile     OBJECT IDENTIFIER ::= { tcg-attribute 11 }
tcg-at-tpmSecurityTarget        OBJECT IDENTIFIER ::= { tcg-attribute 12 }
tcg-at-tbbProtectionProfile     OBJECT IDENTIFIER ::= { tcg-attribute 13 }
tcg-at-tbbSecurityTarget        OBJECT IDENTIFIER ::= { tcg-attribute 14 }
tcg-at-tpmIdLabel               OBJECT IDENTIFIER ::= { tcg-attribute 15 }
tcg-at-tpmSpecification         OBJECT IDENTIFIER ::= { tcg-attribute 16 }
tcg-at-tcgPlatformSpecification OBJECT IDENTIFIER ::= { tcg-attribute 17 }
tcg-at-tpmSecurityAssertions    OBJECT IDENTIFIER ::= { tcg-attribute 18 }
tcg-at-tbbSecurityAssertions    OBJECT IDENTIFIER ::= { tcg-attribute 19 }


tcg-protocol OBJECT IDENTIFIER ::= { tcgOrganization 3 }

tcg-prt-tpmIdProtocol OBJECT IDENTIFIER ::= { tcg-protocol 1 }


tcg-algorithm OBJECT IDENTIFIER ::= { tcgOrganization 4 }

tcg-algorithm-null OBJECT IDENTIFIER ::= { tcg-algorithm 1 }


tcg-ce OBJECT IDENTIFIER ::= { tcgOrganization 6 }

tcg-ce-relevantCredentials                    OBJECT IDENTIFIER ::= { tcg-ce 2 }
tcg-ce-relevantManifests                      OBJECT IDENTIFIER ::= { tcg-ce 3 }
tcg-ce-virtualPlatformAttestationService      OBJECT IDENTIFIER ::= { tcg-ce 4 }
tcg-ce-migrationControllerAttestationService  OBJECT IDENTIFIER ::= { tcg-ce 5 }
tcg-ce-migrationControllerRegistrationService OBJECT IDENTIFIER ::= { tcg-ce 6 }
tcg-ce-virtualPlatformBackupService           OBJECT IDENTIFIER ::= { tcg-ce 7 }

tcg-kp OBJECT IDENTIFIER ::= { tcgOrganization 8 }

tcg-kp-EKCertificate       OBJECT IDENTIFIER ::= { tcg-kp 1 }
tcg-kp-PlatformCertificate OBJECT IDENTIFIER ::= { tcg-kp 2 }
tcg-kp-AIKCertificate      OBJECT IDENTIFIER ::= { tcg-kp 3 }
