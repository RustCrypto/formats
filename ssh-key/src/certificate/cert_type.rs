/// OpenSSH certificate types.
use crate::{decode::Decode, encode::Encode, reader::Reader, writer::Writer, Error, Result};

/// Types of OpenSSH certificates: user or host.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CertType {
    /// User certificate
    User = 1,

    /// Host certificate
    Host = 2,
}

impl CertType {
    /// Is this a host certificate?
    pub fn is_host(self) -> bool {
        self == CertType::Host
    }

    /// Is this a user certificate?
    pub fn is_user(self) -> bool {
        self == CertType::User
    }
}

impl Decode for CertType {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        u32::decode(reader)?.try_into()
    }
}

impl Default for CertType {
    fn default() -> Self {
        Self::User
    }
}

impl Encode for CertType {
    fn encoded_len(&self) -> Result<usize> {
        Ok(4)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        u32::from(*self).encode(writer)
    }
}

impl From<CertType> for u32 {
    fn from(cert_type: CertType) -> u32 {
        cert_type as u32
    }
}

impl TryFrom<u32> for CertType {
    type Error = Error;

    fn try_from(n: u32) -> Result<CertType> {
        match n {
            1 => Ok(CertType::User),
            2 => Ok(CertType::Host),
            _ => Err(Error::FormatEncoding),
        }
    }
}
