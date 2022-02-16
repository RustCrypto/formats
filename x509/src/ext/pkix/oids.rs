//! Object identifier values from PKIX1Implicit and PKIX1Explicit ASN.1 modules

use der::asn1::ObjectIdentifier;

/// OID for CPS qualifier: 1.3.6.1.5.5.7.2.1
pub const QT_CPS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.1");

/// OID for user notice qualifier: 1.3.6.1.5.5.7.2.2
pub const QT_UNOTICE: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.2");

/// OID for OCSP access descriptor: 1.3.6.1.5.5.7.48.1: 1.3.6.1.5.5.7.48.1
pub const AD_OCSP: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.1");

/// OID for caIssuers access descriptor: 1.3.6.1.5.5.7.48.2
pub const AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.2");

/// OID for timeStamping access descriptor: 1.3.6.1.5.5.7.48.3
pub const AD_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.3");

/// OID for caRepository access descriptor: 1.3.6.1.5.5.7.48.5
pub const AD_CA_REPOSITORY: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.5");

/// OID for Name attribute: 2.5.4.41
pub const AT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.41");

/// OID for Surname attribute: 2.5.4.4
pub const AT_SURNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.4");

/// OID for givenName attribute: 2.5.4.42
pub const AT_GIVENNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.42");

/// OID for Initials attribute: 2.5.4.43
pub const AT_INITIALS: ObjectIdentifier = ObjectIdentifier::new("2.5.4.43");

/// OID for generationQualifier attribute: 2.5.4.44
pub const AT_GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.44");

/// OID for commonName attribute: 2.5.4.3
pub const AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.3");

/// OID for localityName attribute: 2.5.4.7
pub const AT_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.7");

/// OID for stateOrProvinceName attribute: 2.5.4.8
pub const AT_STATEORPROVINCENAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.8");

/// OID for street attribute: 2.5.4.9
pub const AT_STREET: ObjectIdentifier = ObjectIdentifier::new("2.5.4.9");

/// OID for organizationName attribute: 2.5.4.10
pub const AT_ORGANIZATIONNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.10");

/// OID for organizationalUnitName attribute: 2.5.4.11
pub const AT_ORGANIZATIONALUNITNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.11");

/// OID for title attribute: 2.5.4.12
pub const AT_TITLE: ObjectIdentifier = ObjectIdentifier::new("2.5.4.12");

/// OID for dnQualifier attribute: 2.5.4.46
pub const AT_DNQUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.46");

/// OID for countryName attribute: 2.5.4.6
pub const AT_COUNTRYNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.6");

/// OID for serialNumber attribute: 2.5.4.5
pub const AT_SERIALNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.5");

/// OID for pseudonym attribute: 2.5.4.65
pub const AT_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new("2.5.4.65");

/// OID for domainComponent attribute: 0.9.2342.19200300.100.1.25
pub const DOMAINCOMPONENT: ObjectIdentifier = ObjectIdentifier::new("0.9.2342.19200300.100.1.25");

/// OID for emailAddress attribute: 1.2.840.113549.1.9.1
pub const EMAILADDRESS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.9.1");

/// OID for anyPolicy extension: 2.5.29.32.0
pub const CE_ANYPOLICY: ObjectIdentifier = ObjectIdentifier::new("2.5.29.32.0");

/// OID for extKeyUsage extension: 2.5.29.37. See [`ExtendedKeyUsage`](type.ExtendedKeyUsage.html).
pub const CE_EXTKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");

/// OID for anyExtendedKeyUsage EKU value: 2.5.29.37.0
pub const CE_ANYEXTENDEDKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37.0");

/// OID for serverAuth key purpose: 1.3.6.1.5.5.7.3.31
pub const KP_SERVERAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.31");

/// OID for clientAuth key purpose: 1.3.6.1.5.5.7.3.32
pub const KP_CLIENTAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.32");

/// OID for codeSigning key purpose: 1.3.6.1.5.5.7.3.33
pub const KP_CODESIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.33");

/// OID for emailProtection key purpose: 1.3.6.1.5.5.7.3.34
pub const KP_EMAILPROTECTION: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.34");

/// OID for timeStamping key purpose: 1.3.6.1.5.5.7.3.38
pub const KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.38");

/// OID for OCSPSigning key purpose: 1.3.6.1.5.5.7.3.39
pub const KP_OCSPSIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.39");

/// OID for authorityInfoAccess extension: 1.3.6.1.5.5.7.1.1
pub const PE_AUTHORITYINFOACCESS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.1.1");

/// OID for subjectInfoAccess extension: 1.3.6.1.5.5.7.1.11
pub const PE_SUBJECTINFOACCESS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.1.11");

/// OID for subjectDirectoryAttributes extension: 2.5.29.9. See [`SubjectDirectoryAttributes`](type.SubjectDirectoryAttributes.html).
pub const CE_SUBJECT_DIRECTORY_ATTRIBUTES: ObjectIdentifier = ObjectIdentifier::new("2.5.29.9");

/// OID for subjectKeyIdentifier extension: 2.5.29.14. See [`SubjectKeyIdentifier`](type.SubjectKeyIdentifier.html).
pub const CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");

/// OID for keyUsage extension: 2.5.29.15. See [`KeyUsage`](type.KeyUsage.html).
pub const CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");

/// OID for privateKeyUsagePeriod extension: 2.5.29.16. See [`PrivateKeyUsagePeriod`](struct.PrivateKeyUsagePeriod.html).
pub const CE_PRIVATE_KEY_USAGE_PERIOD: ObjectIdentifier = ObjectIdentifier::new("2.5.29.16");

/// OID for subjectAltName extension: 2.5.29.17. See [`SubjectAltName`](type.SubjectAltName.html).
pub const CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");

/// OID for issuerAltName extension: 2.5.29.18. See [`IssuerAltName`](type.IssuerAltName.html).
pub const CE_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.18");

/// OID for basicConstraints extension: 2.5.29.19. See [`BasicConstraints`](struct.BasicConstraints.html).
pub const CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");

/// OID for cRLNumber extension: 2.5.29.20
pub const CE_CRLNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.20");

/// OID for cRLReasons extension: 2.5.29.21
pub const CE_CRLREASONS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.21");

/// OID for issuingDistributionPoint extension: 2.5.29.28
pub const CE_ISSUINGDISTRIBUTIONPOINT: ObjectIdentifier = ObjectIdentifier::new("2.5.29.28");

/// OID for deltaCRLIndicator extension: 2.5.29.27
pub const CE_DELTACRLINDICATOR: ObjectIdentifier = ObjectIdentifier::new("2.5.29.27");

/// OID for certificateIssuer extension: 2.5.29.29
pub const CE_CERTIFICATEISSUER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.29");

/// OID for holdInstructionCode extension: 2.5.29.23
pub const CE_HOLDINSTRUCTIONCODE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.23");

/// OID forholdinstruction-callissuer attribute: 2.2.840.10040.2.2
pub const HI_HOLDINSTRUCTION_CALLISSUER: ObjectIdentifier =
    ObjectIdentifier::new("2.2.840.10040.2.2");

/// OID for holdinstruction-reject attribute: 2.2.840.10040.23
pub const HI_HOLDINSTRUCTION_REJECT: ObjectIdentifier = ObjectIdentifier::new("2.2.840.10040.23");

/// OID for invalidityDate extension: 2.5.29.24
pub const CE_INVALIDITYDATE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.24");

/// OID for nameConstraints extension: 2.5.29.30. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const CE_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.30");

/// OID for cRLDistributionPoints extension: 2.5.29.31. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const CE_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.31");

/// OID for certificatePolicies extension: 2.5.29.32. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const CE_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new("2.5.29.32");

/// OID for policyMappings extension: 2.5.29.33. See [`PolicyMappings`](type.PolicyMappings.html).
pub const CE_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.33");

/// OID for authorityKeyIdentifier extension: 2.5.29.35. See [`AuthorityKeyIdentifier`](type.AuthorityKeyIdentifier.html).
pub const CE_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");

/// OID for policyConstraints extension: 2.5.29.36. See [`PolicyConstraints`](struct.PolicyConstraints.html).
pub const CE_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.36");

/// OID for policyConstraints extension: 2.5.29.46. See [`PolicyConstraints`](type.FreshestCRL.html).
pub const CE_FRESHEST_CRL: ObjectIdentifier = ObjectIdentifier::new("2.5.29.46");

/// OID for inhibitAnyPolicy extension: 2.5.29.54. See [`InhibitAnyPolicy`](type.InhibitAnyPolicy.html).
pub const CE_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new("2.5.29.54");

/// OID for ocspNoCheck extension:  1.3.6.1.5.5.7.48.1.5. See [`OcspNoCheck`](type.OcspNoCheck.html).
pub const OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.1.5");

/// OID for PIV NACI extension: 2.16.840.1.101.3.6.9.1. See [`PivNaciIndicator`](type.PivNaciIndicator.html).
pub const PIV_NACI_INDICATOR: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.6.9.1");
