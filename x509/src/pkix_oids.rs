//! Object identifier values from PKIX1Implicit and PKIX1Explicit ASN.1 modules
use crate::ObjectIdentifier;
use alloc::string::{String, ToString};

/// OID for CPS qualifier: 1.3.6.1.5.5.7.2.1
pub const PKIX_QT_CPS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.1");

/// OID for user notice qualifier: 1.3.6.1.5.5.7.2.2
pub const PKIX_QT_UNOTICE: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.2");

/// OID for OCSP access descriptor: 1.3.6.1.5.5.7.48.1: 1.3.6.1.5.5.7.48.1
pub const PKIX_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.1");

/// OID for caIssuers access descriptor: 1.3.6.1.5.5.7.48.2
pub const PKIX_AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.2");

/// OID for timeStamping access descriptor: 1.3.6.1.5.5.7.48.3
pub const PKIX_AD_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.3");

/// OID for caRepository access descriptor: 1.3.6.1.5.5.7.48.5
pub const PKIX_AD_CA_REPOSITORY: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.5");

/// OID for Name attribute: 2.5.4.41
pub const PKIX_AT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.41");

/// OID for Surname attribute: 2.5.4.4
pub const PKIX_AT_SURNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.4");

/// OID for givenName attribute: 2.5.4.42
pub const PKIX_AT_GIVENNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.42");

/// OID for Initials attribute: 2.5.4.43
pub const PKIX_AT_INITIALS: ObjectIdentifier = ObjectIdentifier::new("2.5.4.43");

/// OID for generationQualifier attribute: 2.5.4.44
pub const PKIX_AT_GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.44");

/// OID for commonName attribute: 2.5.4.3
pub const PKIX_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.3");

/// OID for localityName attribute: 2.5.4.7
pub const PKIX_AT_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.7");

/// OID for stateOrProvinceName attribute: 2.5.4.8
pub const PKIX_AT_STATEORPROVINCENAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.8");

/// OID for street attribute: 2.5.4.9
pub const PKIX_AT_STREET: ObjectIdentifier = ObjectIdentifier::new("2.5.4.9");

/// OID for organizationName attribute: 2.5.4.10
pub const PKIX_AT_ORGANIZATIONNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.10");

/// OID for organizationalUnitName attribute: 2.5.4.11
pub const PKIX_AT_ORGANIZATIONALUNITNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.11");

/// OID for title attribute: 2.5.4.12
pub const PKIX_AT_TITLE: ObjectIdentifier = ObjectIdentifier::new("2.5.4.12");

/// OID for dnQualifier attribute: 2.5.4.46
pub const PKIX_AT_DNQUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.46");

/// OID for countryName attribute: 2.5.4.6
pub const PKIX_AT_COUNTRYNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.6");

/// OID for serialNumber attribute: 2.5.4.5
pub const PKIX_AT_SERIALNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.5");

/// OID for pseudonym attribute: 2.5.4.65
pub const PKIX_AT_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new("2.5.4.65");

/// OID for domainComponent attribute: 0.9.2342.19200300.100.1.25
pub const PKIX_DOMAINCOMPONENT: ObjectIdentifier =
    ObjectIdentifier::new("0.9.2342.19200300.100.1.25");

/// OID for emailAddress attribute: 1.2.840.113549.1.9.1
pub const PKIX_EMAILADDRESS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.9.1");

/// OID for anyPolicy extension: 2.5.29.32.0
pub const PKIX_CE_ANYPOLICY: ObjectIdentifier = ObjectIdentifier::new("2.5.29.32.0");

/// OID for extKeyUsage extension: 2.5.29.37. See [`ExtendedKeyUsage`](type.ExtendedKeyUsage.html).
pub const PKIX_CE_EXTKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");

/// OID for anyExtendedKeyUsage EKU value: 2.5.29.37.0
pub const PKIX_CE_ANYEXTENDEDKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37.0");

/// OID for serverAuth key purpose: 1.3.6.1.5.5.7.3.31
pub const PKIX_KP_SERVERAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.31");

/// OID for clientAuth key purpose: 1.3.6.1.5.5.7.3.32
pub const PKIX_KP_CLIENTAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.32");

/// OID for codeSigning key purpose: 1.3.6.1.5.5.7.3.33
pub const PKIX_KP_CODESIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.33");

/// OID for emailProtection key purpose: 1.3.6.1.5.5.7.3.34
pub const PKIX_KP_EMAILPROTECTION: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.34");

/// OID for timeStamping key purpose: 1.3.6.1.5.5.7.3.38
pub const PKIX_KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.38");

/// OID for OCSPSigning key purpose: 1.3.6.1.5.5.7.3.39
pub const PKIX_KP_OCSPSIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.39");

/// OID for authorityInfoAccess extension: 1.3.6.1.5.5.7.1.1
pub const PKIX_PE_AUTHORITYINFOACCESS: ObjectIdentifier =
    ObjectIdentifier::new("1.3.6.1.5.5.7.1.1");

/// OID for subjectInfoAccess extension: 1.3.6.1.5.5.7.1.11
pub const PKIX_PE_SUBJECTINFOACCESS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.1.11");

/// OID for subjectDirectoryAttributes extension: 2.5.29.9. See [`SubjectDirectoryAttributes`](type.SubjectDirectoryAttributes.html).
pub const PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES: ObjectIdentifier =
    ObjectIdentifier::new("2.5.29.9");

/// OID for subjectKeyIdentifier extension: 2.5.29.14. See [`SubjectKeyIdentifier`](type.SubjectKeyIdentifier.html).
pub const PKIX_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.14");

/// OID for keyUsage extension: 2.5.29.15. See [`KeyUsage`](type.KeyUsage.html).
pub const PKIX_CE_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.15");

/// OID for privateKeyUsagePeriod extension: 2.5.29.16. See [`PrivateKeyUsagePeriod`](struct.PrivateKeyUsagePeriod.html).
pub const PKIX_CE_PRIVATE_KEY_USAGE_PERIOD: ObjectIdentifier = ObjectIdentifier::new("2.5.29.16");

/// OID for subjectAltName extension: 2.5.29.17. See [`SubjectAltName`](type.SubjectAltName.html).
pub const PKIX_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.17");

/// OID for issuerAltName extension: 2.5.29.18. See [`IssuerAltName`](type.IssuerAltName.html).
pub const PKIX_CE_ISSUER_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.29.18");

/// OID for basicConstraints extension: 2.5.29.19. See [`BasicConstraints`](struct.BasicConstraints.html).
pub const PKIX_CE_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.19");

/// OID for cRLNumber extension: 2.5.29.20
pub const PKIX_CE_CRLNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.20");

/// OID for cRLReasons extension: 2.5.29.21
pub const PKIX_CE_CRLREASONS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.21");

/// OID for issuingDistributionPoint extension: 2.5.29.28
pub const PKIX_CE_ISSUINGDISTRIBUTIONPOINT: ObjectIdentifier = ObjectIdentifier::new("2.5.29.28");

/// OID for deltaCRLIndicator extension: 2.5.29.27
pub const PKIX_CE_DELTACRLINDICATOR: ObjectIdentifier = ObjectIdentifier::new("2.5.29.27");

/// OID for certificateIssuer extension: 2.5.29.29
pub const PKIX_CE_CERTIFICATEISSUER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.29");

/// OID for holdInstructionCode extension: 2.5.29.23
pub const PKIX_CE_HOLDINSTRUCTIONCODE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.23");

/// OID for holdinstruction-callissuer attribute: 2.2.840.10040.2.2
pub const PKIX_HI_HOLDINSTRUCTION_CALLISSUER: ObjectIdentifier =
    ObjectIdentifier::new("2.2.840.10040.2.2");

/// OID for holdinstruction-reject attribute: 2.2.840.10040.23
pub const PKIX_HI_HOLDINSTRUCTION_REJECT: ObjectIdentifier =
    ObjectIdentifier::new("2.2.840.10040.23");

/// OID for invalidityDate extension: 2.5.29.24
pub const PKIX_CE_INVALIDITYDATE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.24");

/// OID for nameConstraints extension: 2.5.29.30. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const PKIX_CE_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.30");

/// OID for cRLDistributionPoints extension: 2.5.29.31. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const PKIX_CE_CRL_DISTRIBUTION_POINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.31");

/// OID for certificatePolicies extension: 2.5.29.32. See [`CertificatePolicies`](type.CertificatePolicies.html).
pub const PKIX_CE_CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new("2.5.29.32");

/// OID for policyMappings extension: 2.5.29.33. See [`PolicyMappings`](type.PolicyMappings.html).
pub const PKIX_CE_POLICY_MAPPINGS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.33");

/// OID for authorityKeyIdentifier extension: 2.5.29.35. See [`AuthorityKeyIdentifier`](type.AuthorityKeyIdentifier.html).
pub const PKIX_CE_AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.35");

/// OID for policyConstraints extension: 2.5.29.36. See [`PolicyConstraints`](struct.PolicyConstraints.html).
pub const PKIX_CE_POLICY_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.36");

/// OID for freshestCrl extension: 2.5.29.46. See [`FreshestCrl`](type.FreshestCRL.html).
pub const PKIX_CE_FRESHEST_CRL: ObjectIdentifier = ObjectIdentifier::new("2.5.29.46");

/// OID for inhibitAnyPolicy extension: 2.5.29.54. See [`InhibitAnyPolicy`](type.InhibitAnyPolicy.html).
pub const PKIX_CE_INHIBIT_ANY_POLICY: ObjectIdentifier = ObjectIdentifier::new("2.5.29.54");

/// OID for ocspNoCheck extension:  1.3.6.1.5.5.7.48.1.5. See [`OcspNoCheck`](type.OcspNoCheck.html).
pub const PKIX_OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.1.5");

/// OID for PIV NACI extension: 2.16.840.1.101.3.6.9.1. See [`PivNaciIndicator`](type.PivNaciIndicator.html).
pub const PIV_NACI_INDICATOR: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.6.9.1");

// -------------------------------------------------------------------------------------------------
// OIDs from PKIXAlgs-2009
// -------------------------------------------------------------------------------------------------

/// rsaEncryption OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
///     pkcs-1(1) 1 }
pub const PKIXALG_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.1");

/// id-ecPublicKey OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
pub const PKIXALG_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.2.1");

/// id-ecDH OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) schemes(1)
///     ecdh(12) }
pub const PKIXALG_DH: ObjectIdentifier = ObjectIdentifier::new("1.3.132.1.12");

/// secp192r1 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
///     prime(1) 1 }
pub const PKIXALG_SECP192R1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.1");

/// sect163k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 1 }
pub const PKIXALG_SECP163K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.1");

///    sect163r2 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 15 }
pub const PKIXALG_SECP163R2: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.15");

///    secp224r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 33 }
pub const PKIXALG_SECP224R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.33");

///    sect233k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 26 }
pub const PKIXALG_SECP233K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.26");

///    sect233r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 27 }
pub const PKIXALG_SECP233R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.27");

///    secp256r1 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
///     prime(1) 7 }
pub const PKIXALG_SECP256R1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.10045.3.1.7");

///    sect283k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 16 }
pub const PKIXALG_SECP283K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.16");

///    sect283r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 17 }
pub const PKIXALG_SECP283R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.17");

///    secp384r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 34 }
pub const PKIXALG_SECP384R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.34");

///    sect409k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 36 }
pub const PKIXALG_SECP409K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.36");

///    sect409r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 37 }
pub const PKIXALG_SECP409R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.37");

///    secp521r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 35 }
pub const PKIXALG_SECP521R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.35");

///    sect571k1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 38 }
pub const PKIXALG_SECP571K1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.38");

///    sect571r1 OBJECT IDENTIFIER ::= {
///     iso(1) identified-organization(3) certicom(132) curve(0) 39 }
pub const PKIXALG_SECP571R1: ObjectIdentifier = ObjectIdentifier::new("1.3.132.0.39");

/// ecdsa-with-SHA224 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 1 }
pub const PKIXALG_ECDSA_WITH_SHA224: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.1");

/// ecdsa-with-SHA256 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 2 }
pub const PKIXALG_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA384 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 3 }
pub const PKIXALG_ECDSA_WITH_SHA384: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.3");

/// ecdsa-with-SHA512 OBJECT IDENTIFIER ::= {
///     iso(1) member-body(2) us(840) ansi-X9-62(10045) signatures(4)
///     ecdsa-with-SHA2(3) 4 }
pub const PKIXALG_ECDSA_WITH_SHA512: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.10045.4.3.4");

// -------------------------------------------------------------------------------------------------
// OIDs from PKIX1-PSS-OAEP-Algorithms-2009
// -------------------------------------------------------------------------------------------------
//    pkcs-1  OBJECT IDENTIFIER  ::=
//        { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1 }

/// sha224WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 14 }
pub const PKIXALG_SHA224_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.14");

/// sha256WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 11 }
pub const PKIXALG_SHA256_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.11");

/// sha384WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 12 }
pub const PKIXALG_SHA384_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.12");

/// sha512WithRSAEncryption  OBJECT IDENTIFIER  ::=  { pkcs-1 13 }
pub const PKIXALG_SHA512_WITH_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new("1.2.840.113549.1.1.13");

/// id-RSAES-OAEP  OBJECT IDENTIFIER  ::=  { pkcs-1 7 }
pub const PKIXALG_RSAES_OAEP: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.7");

/// id-pSpecified  OBJECT IDENTIFIER  ::=  { pkcs-1 9 }
pub const PKIXALG_PSPECIFIED: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.9");

/// id-mgf1  OBJECT IDENTIFIER  ::=  { pkcs-1 8 }
pub const PKIXALG_MGF1: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.8");

/// id-RSASSA-PSS  OBJECT IDENTIFIER  ::=  { pkcs-1 10 }
pub const PKIXALG_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.1.10");

///       sha-1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
///           oiw(14) secsig(3) algorithm(2) 26 }
pub const PKIXALG_SHA1: ObjectIdentifier = ObjectIdentifier::new("1.3.14.3.2.26");

/// id-sha224  OBJECT IDENTIFIER  ::=
///     { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///     csor(3) algorithms(4) hashalgs(2) 4 }
pub const PKIXALG_SHA224: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.4");

/// id-sha256  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 1 }
pub const PKIXALG_SHA256: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.1");

/// id-sha384  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 2 }
pub const PKIXALG_SHA384: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.2");

/// id-sha512  OBJECT IDENTIFIER  ::=
///        { joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101)
///        csor(3) algorithms(4) hashalgs(2) 3 }
pub const PKIXALG_SHA512: ObjectIdentifier = ObjectIdentifier::new("2.16.840.1.101.3.4.2.3");

/// oid_to_string takes an ObjectIdentifier and returns a String containing a friendly name or a
/// dot notation representation of the OID, i.e., 1.2.3.4, if no friendly name is found.
pub fn oid_to_string(oid: &ObjectIdentifier) -> String {
    let s = oid_to_str(oid);
    if s.is_empty() {
        return oid.to_string();
    }
    s.to_string()
}

/// oid_to_str takes an ObjectIdentifier and returns a str containing a friendly name or an empty
/// string if no friendly name is found.
pub fn oid_to_str(oid: &ObjectIdentifier) -> &'static str {
    match *oid {
        PKIX_QT_CPS => "qtCps",
        PKIX_QT_UNOTICE => "qtUnotice",
        PKIX_AD_OCSP => "adOcsp",
        PKIX_AD_CA_ISSUERS => "adCaIssuers",
        PKIX_AD_TIME_STAMPING => "adTimeStamping",
        PKIX_AD_CA_REPOSITORY => "adCaRepository",
        PKIX_AT_NAME => "name",
        PKIX_AT_SURNAME => "sn",
        PKIX_AT_GIVENNAME => "givenName",
        PKIX_AT_INITIALS => "initials",
        PKIX_AT_GENERATION_QUALIFIER => "generationQualifier",
        PKIX_AT_COMMON_NAME => "cn",
        PKIX_AT_LOCALITY_NAME => "l",
        PKIX_AT_STATEORPROVINCENAME => "st",
        PKIX_AT_STREET => "street",
        PKIX_AT_ORGANIZATIONNAME => "ou",
        PKIX_AT_ORGANIZATIONALUNITNAME => "sn",
        PKIX_AT_TITLE => "title",
        PKIX_AT_DNQUALIFIER => "dnQualifier",
        PKIX_AT_COUNTRYNAME => "c",
        PKIX_AT_SERIALNUMBER => "serialNumber",
        PKIX_AT_PSEUDONYM => "pseudonym",
        PKIX_DOMAINCOMPONENT => "dc",
        PKIX_EMAILADDRESS => "emailAddress",
        PKIX_CE_ANYPOLICY => "anyPolicy",
        PKIX_CE_EXTKEYUSAGE => "extKeyUsage",
        PKIX_CE_ANYEXTENDEDKEYUSAGE => "anyExtendedKeyUsage",
        PKIX_KP_SERVERAUTH => "serverAuth",
        PKIX_KP_CLIENTAUTH => "clientAuth",
        PKIX_KP_CODESIGNING => "codeSigning",
        PKIX_KP_EMAILPROTECTION => "emailProtection",
        PKIX_KP_TIMESTAMPING => "timeStamping",
        PKIX_KP_OCSPSIGNING => "OCSPSigning",
        PKIX_PE_AUTHORITYINFOACCESS => "authorityInfoAccess",
        PKIX_PE_SUBJECTINFOACCESS => "subjectInfoAccess",
        PKIX_CE_SUBJECT_DIRECTORY_ATTRIBUTES => "subjectDirectoryAttributes",
        PKIX_CE_SUBJECT_KEY_IDENTIFIER => "subjectKeyIdentifier",
        PKIX_CE_KEY_USAGE => "keyUsage",
        PKIX_CE_PRIVATE_KEY_USAGE_PERIOD => "privateKeyUsagePeriod",
        PKIX_CE_SUBJECT_ALT_NAME => "subjectAltName",
        PKIX_CE_ISSUER_ALT_NAME => "issuerAltName",
        PKIX_CE_BASIC_CONSTRAINTS => "basicConstraints",
        PKIX_CE_CRLNUMBER => "cRLNumber",
        PKIX_CE_CRLREASONS => "cRLReasons",
        PKIX_CE_ISSUINGDISTRIBUTIONPOINT => "issuingDistributionPoint",
        PKIX_CE_DELTACRLINDICATOR => "deltaCRLIndicator",
        PKIX_CE_CERTIFICATEISSUER => "certificateIssuer",
        PKIX_CE_HOLDINSTRUCTIONCODE => "holdInstructionCode",
        PKIX_HI_HOLDINSTRUCTION_CALLISSUER => "holdinstruction-callissuer",
        PKIX_HI_HOLDINSTRUCTION_REJECT => "holdinstruction-reject",
        PKIX_CE_INVALIDITYDATE => "invalidityDate",
        PKIX_CE_NAME_CONSTRAINTS => "nameConstraints",
        PKIX_CE_CRL_DISTRIBUTION_POINTS => "cRLDistributionPoints",
        PKIX_CE_CERTIFICATE_POLICIES => "certificatePolicies",
        PKIX_CE_POLICY_MAPPINGS => "policyMappings",
        PKIX_CE_AUTHORITY_KEY_IDENTIFIER => "authorityKeyIdentifier",
        PKIX_CE_POLICY_CONSTRAINTS => "policyConstraints",
        PKIX_CE_FRESHEST_CRL => "freshestCrl",
        PKIX_CE_INHIBIT_ANY_POLICY => "inhibitAnyPolicy",
        PKIX_OCSP_NOCHECK => "ocspNoCheck",
        PIV_NACI_INDICATOR => "pivNaciIdendicator",
        PKIXALG_RSA_ENCRYPTION => "rsaEncryption",
        PKIXALG_EC_PUBLIC_KEY => "ecPublicKey",
        PKIXALG_DH => "ecDH",
        PKIXALG_SECP192R1 => "secp192r1",
        PKIXALG_SECP163K1 => "sect163k1",
        PKIXALG_SECP163R2 => "sect163r2",
        PKIXALG_SECP224R1 => "secp224r1",
        PKIXALG_SECP233K1 => "sect233k1",
        PKIXALG_SECP233R1 => "sect233r1",
        PKIXALG_SECP256R1 => "secp256r1",
        PKIXALG_SECP283K1 => "sect283k1",
        PKIXALG_SECP283R1 => "sect283r1",
        PKIXALG_SECP384R1 => "secp384r1",
        PKIXALG_SECP409K1 => "sect409k1",
        PKIXALG_SECP409R1 => "sect409r1",
        PKIXALG_SECP521R1 => "secp521r1",
        PKIXALG_SECP571K1 => "sect571k1",
        PKIXALG_SECP571R1 => "sect571r1",
        PKIXALG_ECDSA_WITH_SHA224 => "ecdsa-with-SHA224",
        PKIXALG_ECDSA_WITH_SHA256 => "ecdsa-with-SHA256",
        PKIXALG_ECDSA_WITH_SHA384 => "ecdsa-with-SHA384",
        PKIXALG_ECDSA_WITH_SHA512 => "ecdsa-with-SHA512",
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => "sha224WithRSAEncryption",
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => "sha256WithRSAEncryption",
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => "sha384WithRSAEncryption",
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => "sha512WithRSAEncryption",
        PKIXALG_RSAES_OAEP => "RSAES-OAEP",
        PKIXALG_PSPECIFIED => "pSpecified",
        PKIXALG_MGF1 => "MFG1",
        PKIXALG_RSASSA_PSS => "sha1",
        PKIXALG_SHA224 => "sha224",
        PKIXALG_SHA256 => "sha256",
        PKIXALG_SHA384 => "sha384",
        PKIXALG_SHA512 => "sha512",
        _ => "",
    }
}
