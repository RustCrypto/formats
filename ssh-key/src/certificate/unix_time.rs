//! Unix timestamps.

use crate::{decode::Decode, encode::Encode, reader::Reader, writer::Writer, Error, Result};
use core::fmt;
use core::fmt::Formatter;

#[cfg(feature = "std")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum allowed value for a Unix timestamp:
///
/// 9999-12-31 23:59:59 UTC
///
/// This is a sanity limit intended to catch nonsense values which are
/// excessively far in the future. Otherwise the limit is `i64::MAX`.
pub const MAX_SECS: u64 = 253402300799;

/// Unix timestamps as used in OpenSSH certificates.
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub(super) struct UnixTime {
    /// Number of seconds since the Unix epoch
    secs: u64,

    /// System time corresponding to this Unix timestamp
    #[cfg(feature = "std")]
    time: SystemTime,
}

impl UnixTime {
    /// Create a new Unix timestamp.
    ///
    /// `secs` is the number of seconds since the Unix epoch and must be less
    /// than or equal to `i64::MAX`.
    #[cfg(not(feature = "std"))]
    pub fn new(secs: u64) -> Result<Self> {
        if secs <= MAX_SECS {
            Ok(Self { secs })
        } else {
            Err(Error::Time)
        }
    }

    /// Create a new Unix timestamp.
    ///
    /// This version requires `std` and ensures there's a valid `SystemTime`
    /// representation with an infallible conversion (which also improves the
    /// `Debug` output)
    #[cfg(feature = "std")]
    pub fn new(secs: u64) -> Result<Self> {
        if secs > MAX_SECS {
            return Err(Error::Time);
        }

        match UNIX_EPOCH.checked_add(Duration::from_secs(secs)) {
            Some(time) => Ok(Self { secs, time }),
            None => Err(Error::Time),
        }
    }

    /// Get the current time as a Unix timestamp.
    #[cfg(all(feature = "std", feature = "fingerprint"))]
    pub fn now() -> Result<Self> {
        SystemTime::now().try_into()
    }
}

impl Decode for UnixTime {
    fn decode(reader: &mut impl Reader) -> Result<Self> {
        u64::decode(reader)?.try_into()
    }
}

impl Encode for UnixTime {
    fn encoded_len(&self) -> Result<usize> {
        self.secs.encoded_len()
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<()> {
        self.secs.encode(writer)
    }
}

impl From<UnixTime> for u64 {
    fn from(unix_time: UnixTime) -> u64 {
        unix_time.secs
    }
}

#[cfg(feature = "std")]
impl From<UnixTime> for SystemTime {
    fn from(unix_time: UnixTime) -> SystemTime {
        unix_time.time
    }
}

impl TryFrom<u64> for UnixTime {
    type Error = Error;

    fn try_from(unix_secs: u64) -> Result<UnixTime> {
        Self::new(unix_secs)
    }
}

#[cfg(feature = "std")]
impl TryFrom<SystemTime> for UnixTime {
    type Error = Error;

    fn try_from(time: SystemTime) -> Result<UnixTime> {
        Self::new(time.duration_since(UNIX_EPOCH)?.as_secs())
    }
}

impl fmt::Debug for UnixTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.secs)
    }
}

#[cfg(test)]
mod tests {
    use super::{UnixTime, MAX_SECS};
    use crate::Error;

    #[test]
    fn new_with_max_secs() {
        assert!(UnixTime::new(MAX_SECS).is_ok());
    }

    #[test]
    fn new_over_max_secs_returns_error() {
        assert_eq!(UnixTime::new(MAX_SECS + 1), Err(Error::Time));
    }
}
