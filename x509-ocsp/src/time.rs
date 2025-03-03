//! OCSP GeneralizedTime implementation

use der::{
    DateTime,
    asn1::{GeneralizedTime, UtcTime},
};
use x509_cert::{impl_newtype, time::Time};

/// [`GeneralizedTime`] wrapper for easy conversion from legacy `UTCTime`
///
/// OCSP does not support `UTCTime` while many other X.509 structures do.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OcspGeneralizedTime(pub GeneralizedTime);

impl_newtype!(OcspGeneralizedTime, GeneralizedTime);

#[cfg(feature = "std")]
impl TryFrom<std::time::SystemTime> for OcspGeneralizedTime {
    type Error = der::Error;

    fn try_from(other: std::time::SystemTime) -> Result<Self, Self::Error> {
        Ok(Self(GeneralizedTime::from_system_time(other)?))
    }
}

impl From<DateTime> for OcspGeneralizedTime {
    fn from(other: DateTime) -> Self {
        Self(GeneralizedTime::from_date_time(other))
    }
}

impl From<UtcTime> for OcspGeneralizedTime {
    fn from(other: UtcTime) -> Self {
        Self(GeneralizedTime::from_date_time(other.to_date_time()))
    }
}

impl From<Time> for OcspGeneralizedTime {
    fn from(other: Time) -> Self {
        match other {
            Time::UtcTime(t) => t.into(),
            Time::GeneralTime(t) => t.into(),
        }
    }
}
