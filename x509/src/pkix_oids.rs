//! Object identifier values from PKIX1Implicit and PKIX1Explicit ASN.1 modules
use crate::ObjectIdentifier;

/// OID for CPS qualifier
pub const PKIX_QT_CPS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.1");

/// OID for user notice qualifier
pub const PKIX_QT_UNOTICE: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.2.2");

/// OID for OCSP access descriptor
pub const PKIX_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.1");

/// OID for caIssuers access descriptor
pub const PKIX_AD_CA_ISSUERS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.2");

/// OID for timeStamping access descriptor
pub const PKIX_AD_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.3");

/// OID for caRepository access descriptor
pub const PKIX_AD_CA_REPOSITORY: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.48.5");

/// OID for Name attribute
pub const PKIX_AT_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.41");

/// OID for Surname attribute
pub const PKIX_AT_SURNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.4");

/// OID for givenName attribute
pub const PKIX_AT_GIVENNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.42");

/// OID for Initials attribute
pub const PKIX_AT_INITIALS: ObjectIdentifier = ObjectIdentifier::new("2.5.4.43");

/// OID for generationQualifier attribute
pub const PKIX_AT_GENERATION_QUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.44");

/// OID for commonName attribute
pub const PKIX_AT_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.3");

/// OID for localityName attribute
pub const PKIX_AT_LOCALITY_NAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.7");

/// OID for stateOrProvinceName attribute
pub const PKIX_AT_STATEORPROVINCENAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.8");

/// OID for organizationName attribute
pub const PKIX_AT_ORGANIZATIONNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.10");

/// OID for organizationalUnitName attribute
pub const PKIX_AT_ORGANIZATIONALUNITNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.11");

/// OID for title attribute
pub const PKIX_AT_TITLE: ObjectIdentifier = ObjectIdentifier::new("2.5.4.12");

/// OID for dnQualifier attribute
pub const PKIX_AT_DNQUALIFIER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.46");

/// OID for countryName attribute
pub const PKIX_AT_COUNTRYNAME: ObjectIdentifier = ObjectIdentifier::new("2.5.4.6");

/// OID for serialNumber attribute
pub const PKIX_AT_SERIALNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.4.5");

/// OID for pseudonym attribute
pub const PKIX_AT_PSEUDONYM: ObjectIdentifier = ObjectIdentifier::new("2.5.4.65");

/// OID for domainComponent attribute
pub const PKIX_DOMAINCOMPONENT: ObjectIdentifier =
    ObjectIdentifier::new("0.9.2342.19200300.100.1.25");

/// OID for emailAddress attribute
pub const PKIX_EMAILADDRESS: ObjectIdentifier = ObjectIdentifier::new("1.2.840.113549.1.9.1");

/// OID for anyPolicy extension
pub const PKIX_CE_ANYPOLICY: ObjectIdentifier = ObjectIdentifier::new("2.5.29.32.0");

/// OID for extKeyUsage extension
pub const PKIX_CE_EXTKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37");

/// OID for anyExtendedKeyUsage EKU value
pub const PKIX_CE_ANYEXTENDEDKEYUSAGE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.37.0");

/// OID for serverAuth key purpose
pub const PKIX_KP_SERVERAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.31");

/// OID for clientAuth key purpose
pub const PKIX_KP_CLIENTAUTH: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.32");

/// OID for codeSigning key purpose
pub const PKIX_KP_CODESIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.33");

/// OID for emailProtection key purpose
pub const PKIX_KP_EMAILPROTECTION: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.34");

/// OID for timeStamping key purpose
pub const PKIX_KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.38");

/// OID for OCSPSigning key purpose
pub const PKIX_KP_OCSPSIGNING: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.3.39");

/// OID for authorityInfoAccess extension
pub const PKIX_PE_AUTHORITYINFOACCESS: ObjectIdentifier =
    ObjectIdentifier::new("1.3.6.1.5.5.7.1.1");

/// OID for subjectInfoAccess extension
pub const PKIX_PE_SUBJECTINFOACCESS: ObjectIdentifier = ObjectIdentifier::new("1.3.6.1.5.5.7.1.11");

/// OID for cRLNumber extension
pub const PKIX_CE_CRLNUMBER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.20");

/// OID for issuingDistributionPoint extension
pub const PKIX_CE_ISSUINGDISTRIBUTIONPOINT: ObjectIdentifier = ObjectIdentifier::new("2.5.29.28");

/// OID for deltaCRLIndicator extension
pub const PKIX_CE_DELTACRLINDICATOR: ObjectIdentifier = ObjectIdentifier::new("2.5.29.27");

/// OID for cRLReasons extension
pub const PKIX_CE_CRLREASONS: ObjectIdentifier = ObjectIdentifier::new("2.5.29.21");

/// OID for certificateIssuer extension
pub const PKIX_CE_CERTIFICATEISSUER: ObjectIdentifier = ObjectIdentifier::new("2.5.29.29");

/// OID for holdInstructionCode extension
pub const PKIX_CE_HOLDINSTRUCTIONCODE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.23");

/// OID forholdinstruction-callissuer  attribute
pub const PKIX_HI_HOLDINSTRUCTION_CALLISSUER: ObjectIdentifier =
    ObjectIdentifier::new("2.2.840.10040.2.2");

/// OID for holdinstruction-reject attribute
pub const PKIX_HI_HOLDINSTRUCTION_REJECT: ObjectIdentifier =
    ObjectIdentifier::new("2.2.840.10040.23");

/// OID for invalidityDate extension
pub const PKIX_CE_INVALIDITYDATE: ObjectIdentifier = ObjectIdentifier::new("2.5.29.24");
