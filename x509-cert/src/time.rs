//! X.501 time types as defined in RFC 5280

use core::{fmt, marker::PhantomData, str::FromStr, time::Duration};
use der::asn1::{GeneralizedTime, UtcTime};
use der::{Choice, DateTime, DecodeValue, Encode, Header, Length, Reader, Sequence, ValueOrd};

#[cfg(feature = "std")]
use std::time::SystemTime;

use crate::certificate::{Profile, Rfc5280};

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
    /// Legacy UTC time (has 2-digit year, valid from 1970 to 2049).
    ///
    /// Note: RFC 5280 specifies 1950-2049, however due to common operations working on
    /// `UNIX_EPOCH` this implementation's lower bound is 1970.
    #[asn1(type = "UTCTime")]
    UtcTime(UtcTime),

    /// Modern [`GeneralizedTime`] encoding with 4-digit year.
    #[asn1(type = "GeneralizedTime")]
    GeneralTime(GeneralizedTime),
}

impl Time {
    /// Time used for Certificate who do not expire.
    pub const INFINITY: Time =
        Time::GeneralTime(GeneralizedTime::from_date_time(DateTime::INFINITY));

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
    pub fn to_system_time(&self) -> SystemTime {
        match self {
            Time::UtcTime(t) => t.to_system_time(),
            Time::GeneralTime(t) => t.to_system_time(),
        }
    }

    /// Convert time to UTCTime representation
    /// As per RFC 5280: 4.1.2.5, date through 2049 should be expressed as UTC Time.
    pub(crate) fn rfc5280_adjust_utc_time(&mut self) -> der::Result<()> {
        if let Time::GeneralTime(t) = self {
            let date = t.to_date_time();
            if date.year() <= UtcTime::MAX_YEAR {
                *self = Time::UtcTime(UtcTime::from_date_time(date)?);
            }
        }

        Ok(())
    }

    /// Creates a `Time` from the current date.
    #[cfg(feature = "std")]
    pub fn now() -> der::Result<Self> {
        SystemTime::now().try_into()
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl From<DateTime> for Time {
    fn from(time: DateTime) -> Time {
        UtcTime::from_date_time(time)
            .map(Self::UtcTime)
            .unwrap_or_else(|_e| Self::GeneralTime(GeneralizedTime::from_date_time(time)))
    }
}

impl FromStr for Time {
    type Err = der::Error;

    fn from_str(input: &str) -> der::Result<Self> {
        let datetime = DateTime::from_str(input)?;

        Ok(Self::from(datetime))
    }
}

#[cfg(feature = "std")]
impl From<Time> for SystemTime {
    fn from(time: Time) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
impl From<&Time> for SystemTime {
    fn from(time: &Time) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
impl TryFrom<SystemTime> for Time {
    type Error = der::Error;

    fn try_from(time: SystemTime) -> der::Result<Time> {
        let datetime = DateTime::from_system_time(time)?;

        Ok(datetime.into())
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueOrd)]
pub struct Validity<P: Profile = Rfc5280> {
    /// notBefore value
    pub not_before: Time,

    /// notAfter value
    pub not_after: Time,

    _profile: PhantomData<P>,
}

impl<P> Validity<P>
where
    P: Profile,
{
    /// Creates a `Validity` with the provided bounds
    pub const fn new(not_before: Time, not_after: Time) -> Self {
        Self {
            not_before,
            not_after,
            _profile: PhantomData,
        }
    }

    /// Creates a `Validity` which starts now and lasts for `duration`.
    #[cfg(feature = "std")]
    pub fn from_now(duration: Duration) -> der::Result<Self> {
        let now = SystemTime::now();
        let then = now + duration;

        Ok(Self {
            not_before: Time::try_from(now)?,
            not_after: Time::try_from(then)?,
            _profile: PhantomData,
        })
    }

    /// Creates a `Validity` which starts now and does not expire.
    #[cfg(all(feature = "std", feature = "hazmat"))]
    pub fn infinity() -> der::Result<Self> {
        let now = SystemTime::now();

        Ok(Self {
            not_before: Time::try_from(now)?,
            not_after: Time::INFINITY,
            _profile: PhantomData,
        })
    }
}

impl<'a, P: Profile> DecodeValue<'a> for Validity<P> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let not_before = reader.decode()?;
        let not_after = reader.decode()?;
        let out = Self {
            not_before,
            not_after,
            _profile: PhantomData,
        };

        Ok(out)
    }
}

impl<P: Profile> ::der::EncodeValue for Validity<P> {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        [
            P::time_encoding(self.not_before)?.encoded_len()?,
            P::time_encoding(self.not_after)?.encoded_len()?,
        ]
        .into_iter()
        .try_fold(Length::ZERO, |acc, len| acc + len)
    }
    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        P::time_encoding(self.not_before)?.encode(writer)?;
        P::time_encoding(self.not_after)?.encode(writer)?;
        Ok(())
    }
}

impl<P: Profile> Sequence<'_> for Validity<P> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_time() {
        let time = Time::from_str("1970-01-01T00:00:00Z").expect("parse date from string");
        assert!(matches!(time, Time::UtcTime(_)));
        assert_eq!(alloc::format!("{}", time), "1970-01-01T00:00:00Z");

        let time = Time::from_str("2020-01-01T00:00:00Z").expect("parse date from string");
        assert!(matches!(time, Time::UtcTime(_)));
        assert_eq!(alloc::format!("{}", time), "2020-01-01T00:00:00Z");

        let time = Time::from_str("2049-12-31T23:59:59Z").expect("parse date from string");
        assert!(matches!(time, Time::UtcTime(_)));
        assert_eq!(alloc::format!("{}", time), "2049-12-31T23:59:59Z");

        let time = Time::from_str("2050-01-01T00:00:00Z").expect("parse date from string");
        assert!(matches!(time, Time::GeneralTime(_)));
        assert_eq!(alloc::format!("{}", time), "2050-01-01T00:00:00Z");
    }
}
