//! X.501 time types as defined in RFC 5280

use core::fmt;
use core::time::Duration;
use der::asn1::{GeneralizedTime, UtcTime};
use der::{Choice, DateTime, Decode, Error, Result, Sequence, ValueOrd};

#[cfg(feature = "std")]
use std::time::SystemTime;

/// X.501 `Time` as defined in [RFC 5280 Section 4.1.2.5].
///
/// Schema definition from [RFC 5280 Appendix A]:
///
/// ```text
/// Time ::= CHOICE {
///      utcTime        UTCTime,
///      generalTime    GeneralizedTime
/// }
/// ```
///
/// [RFC 5280 Section 4.1.2.5]: https://tools.ietf.org/html/rfc5280#section-4.1.2.5
/// [RFC 5280 Appendix A]: https://tools.ietf.org/html/rfc5280#page-117
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Choice, Copy, Clone, Debug, Eq, PartialEq, ValueOrd)]
pub enum Time {
    /// Legacy UTC time (has 2-digit year, valid only through 2050).
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    /// Modern [`GeneralizedTime`] encoding with 4-digit year.
    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

impl Time {
    /// Get duration since `UNIX_EPOCH`.
    pub fn to_unix_duration(self) -> Duration {
        match self {
            Time::UtcTime(t) => t.to_unix_duration(),
            Time::GeneralTime(t) => t.to_unix_duration(),
        }
    }

    /// Get Time as DateTime
    pub fn to_date_time(&self) -> DateTime {
        match self {
            Time::UtcTime(t) => t.to_date_time(),
            Time::GeneralTime(t) => t.to_date_time(),
        }
    }

    /// Convert to [`SystemTime`].
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn to_system_time(&self) -> SystemTime {
        match self {
            Time::UtcTime(t) => t.to_system_time(),
            Time::GeneralTime(t) => t.to_system_time(),
        }
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        write!(f, "{}", self.to_date_time())
    }
}

impl From<UtcTime> for Time {
    fn from(time: UtcTime) -> Time {
        Time::UtcTime(time)
    }
}

impl From<GeneralizedTime> for Time {
    fn from(time: GeneralizedTime) -> Time {
        Time::GeneralTime(time)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<Time> for SystemTime {
    fn from(time: Time) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<&Time> for SystemTime {
    fn from(time: &Time) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<SystemTime> for Time {
    type Error = Error;

    fn try_from(time: SystemTime) -> Result<Time> {
        Ok(GeneralizedTime::try_from(time)?.into())
    }
}

/// X.501 `Validity` as defined in [RFC 5280 Section 4.1.2.5]
///
/// ```text
/// Validity ::= SEQUENCE {
///     notBefore      Time,
///     notAfter       Time
/// }
/// ```
/// [RFC 5280 Section 4.1.2.5]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.5
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
pub struct Validity {
    /// notBefore value
    pub not_before: Time,

    /// notAfter value
    pub not_after: Time,
}

impl Validity {
    /// Creates a `Validity` which starts now and lasts for `duration`.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_now(duration: Duration) -> Result<Self> {
        let now = SystemTime::now();
        let then = now + duration;

        Ok(Self {
            not_before: Time::try_from(now)?,
            not_after: Time::try_from(then)?,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Validity {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::from_der(bytes)
    }
}
