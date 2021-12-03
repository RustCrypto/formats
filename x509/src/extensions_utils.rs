//! Utility functions and enums related to X.509 extensions

use alloc::vec::Vec;
use core::fmt;
use der::asn1::BitString;

/// Enum representing values from the KeyUsage structure
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyUsageValues {
    /// DigitalSignature
    DigitalSignature = 0,
    /// NonRepudiation
    NonRepudiation = 1,
    /// KeyEncipherment
    KeyEncipherment = 2,
    /// DataEncipherment
    DataEncipherment = 3,
    /// KeyAgreement
    KeyAgreement = 4,
    /// KeyCertSign
    KeyCertSign = 5,
    /// CRLSign
    CRLSign = 6,
    /// EncipherOnly
    EncipherOnly = 7,
    /// DecipherOnly
    DecipherOnly = 8,
}

impl KeyUsageValues {
    fn as_str(self) -> &'static str {
        match self {
            KeyUsageValues::DigitalSignature => "DigitalSignature",
            KeyUsageValues::NonRepudiation => "NonRepudiation",
            KeyUsageValues::KeyEncipherment => "KeyEncipherment",
            KeyUsageValues::DataEncipherment => "DataEncipherment",
            KeyUsageValues::KeyAgreement => "KeyAgreement",
            KeyUsageValues::KeyCertSign => "KeyCertSign",
            KeyUsageValues::CRLSign => "CRLSign",
            KeyUsageValues::EncipherOnly => "EncipherOnly",
            KeyUsageValues::DecipherOnly => "DecipherOnly",
        }
    }
}

impl fmt::Display for KeyUsageValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(self.as_str())
    }
}

/// Takes a BitString that contains one or two bytes and returns a Vec containing
/// enum values representing the KeyUsage values that were set in the BitString
pub fn get_key_usage_values(ku: &BitString<'_>) -> Vec<KeyUsageValues> {
    let mut retval: Vec<KeyUsageValues> = Vec::new();
    let b = ku.raw_bytes();
    if 0x80 == 0x80 & b[0] {
        retval.push(KeyUsageValues::DigitalSignature);
    }
    if 0x40 == 0x40 & b[0] {
        retval.push(KeyUsageValues::NonRepudiation);
    }
    if 0x20 == 0x20 & b[0] {
        retval.push(KeyUsageValues::KeyEncipherment);
    }
    if 0x10 == 0x10 & b[0] {
        retval.push(KeyUsageValues::DataEncipherment);
    }
    if 0x08 == 0x08 & b[0] {
        retval.push(KeyUsageValues::KeyAgreement);
    }
    if 0x04 == 0x04 & b[0] {
        retval.push(KeyUsageValues::KeyCertSign);
    }
    if 0x02 == 0x02 & b[0] {
        retval.push(KeyUsageValues::CRLSign);
    }
    if 0x01 == 0x01 & b[0] {
        retval.push(KeyUsageValues::EncipherOnly);
    }

    if 2 == b.len() && 0x80 == 0x80 & b[1] {
        retval.push(KeyUsageValues::DecipherOnly);
    }

    retval
}

/// ReasonFlags ::= BIT STRING {
///      unused                  (0),
///      keyCompromise           (1),
///      cACompromise            (2),
///      affiliationChanged      (3),
///      superseded              (4),
///      cessationOfOperation    (5),
///      certificateHold         (6),
///      privilegeWithdrawn      (7),
///      aACompromise            (8) }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReasonFlagsValues {
    /// unused                  (0),
    pub unused: bool,
    /// keyCompromise           (1),
    pub key_compromise: bool,
    /// cACompromise            (2),
    pub ca_compromise: bool,
    /// affiliationChanged      (3),
    pub affiliation_changed: bool,
    /// superseded              (4),
    pub superseded: bool,
    /// cessationOfOperation    (5),
    pub cessation_of_operation: bool,
    /// certificateHold         (6),
    pub certificate_hold: bool,
    /// privilegeWithdrawn      (7),
    pub remove_from_crl: bool,
    /// aACompromise            (8)
    pub aa_compromise: bool,
}

/// Takes a BitString that contains one or two bytes and returns a Vec containing
/// enum values representing the KeyUsage values that were set in the BitString
pub fn get_reason_flags_values(ku: &BitString<'_>) -> ReasonFlagsValues {
    let b = ku.raw_bytes();
    let unused = 0x80 == 0x80 & b[0];
    let key_compromise = 0x40 == 0x40 & b[0];
    let ca_compromise = 0x20 == 0x20 & b[0];
    let affiliation_changed = 0x10 == 0x10 & b[0];
    let superseded = 0x08 == 0x08 & b[0];
    let cessation_of_operation = 0x04 == 0x04 & b[0];
    let certificate_hold = 0x02 == 0x02 & b[0];
    let remove_from_crl = 0x01 == 0x01 & b[0];
    let aa_compromise = 2 == b.len() && 0x80 == 0x80 & b[1];

    let retval: ReasonFlagsValues = ReasonFlagsValues {
        unused,
        key_compromise,
        ca_compromise,
        affiliation_changed,
        superseded,
        cessation_of_operation,
        certificate_hold,
        remove_from_crl,
        aa_compromise,
    };

    retval
}
