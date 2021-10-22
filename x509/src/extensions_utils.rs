//! Utility functions and enums related to X.509 extensions

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use der::asn1::BitString;

/// Enum representing values from the KeyUsage structure
#[derive(Clone, Debug, Eq, PartialEq)]
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

impl fmt::Display for KeyUsageValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match *self {
            KeyUsageValues::DigitalSignature => write!(f, "DigitalSignature"),
            KeyUsageValues::NonRepudiation => write!(f, "NonRepudiation"),
            KeyUsageValues::KeyEncipherment => write!(f, "KeyEncipherment"),
            KeyUsageValues::DataEncipherment => write!(f, "DataEncipherment"),
            KeyUsageValues::KeyAgreement => write!(f, "KeyAgreement"),
            KeyUsageValues::KeyCertSign => write!(f, "KeyCertSign"),
            KeyUsageValues::CRLSign => write!(f, "CRLSign"),
            KeyUsageValues::EncipherOnly => write!(f, "EncipherOnly"),
            KeyUsageValues::DecipherOnly => write!(f, "DecipherOnly"),
        }
    }
}

#[cfg(feature = "alloc")]
/// Takes a BitString that contains one or two bytes and returns a Vec containing
/// enum values representing the KeyUsage values that were set in the BitString
pub fn get_key_usage_values<'a>(ku: &BitString<'a>) -> Vec<KeyUsageValues> {
    let mut retval: Vec<KeyUsageValues> = Vec::new();
    let b = ku.as_bytes();
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
