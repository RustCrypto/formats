//! Date and time functionality shared between various ASN.1 types
//! (e.g. `GeneralizedTime`, `UTCTime`)

// Adapted from the `humantime` crate.
// Copyright (c) 2016 The humantime Developers
// Released under the MIT OR Apache 2.0 licenses

use crate::{Encoder, Error, ErrorKind, Result, Tag};
use core::{fmt, str::FromStr, time::Duration};

#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "time")]
use time::PrimitiveDateTime;

/// Minimum year allowed in [`DateTime`] values.
const MIN_YEAR: u16 = 1970;

/// Maximum duration since `UNIX_EPOCH` which can be represented as a
/// [`DateTime`] (non-inclusive).
///
/// This corresponds to: 9999-12-31T23:59:59Z
const MAX_UNIX_DURATION: Duration = Duration::from_secs(253_402_300_799);

/// Date-and-time type shared by multiple ASN.1 types
/// (e.g. `GeneralizedTime`, `UTCTime`).
///
/// Following conventions from RFC 5280, this type is always Z-normalized
/// (i.e. represents a UTC time). However, it isn't named "UTC time" in order
/// to prevent confusion with ASN.1 `UTCTime`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct DateTime {
    /// Full year (e.g. 2000).
    ///
    /// Must be >=1970 to permit positive conversions to Unix time.
    year: u16,

    /// Month (1-12)
    month: u8,

    /// Day of the month (1-31)
    day: u8,

    /// Hour (0-23)
    hour: u8,

    /// Minutes (0-59)
    minutes: u8,

    /// Seconds (0-59)
    seconds: u8,

    /// [`Duration`] since the Unix epoch.
    unix_duration: Duration,
}

impl DateTime {
    /// Create a new [`DateTime`] from the given UTC time components.
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minutes: u8, seconds: u8) -> Result<Self> {
        // Basic validation of the components.
        if year < MIN_YEAR
            || !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || !(0..=23).contains(&hour)
            || !(0..=59).contains(&minutes)
            || !(0..=59).contains(&seconds)
        {
            return Err(ErrorKind::DateTime.into());
        }

        let leap_years =
            ((year - 1) - 1968) / 4 - ((year - 1) - 1900) / 100 + ((year - 1) - 1600) / 400;

        let is_leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);

        let (mut ydays, mdays): (u16, u8) = match month {
            1 => (0, 31),
            2 if is_leap_year => (31, 29),
            2 => (31, 28),
            3 => (59, 31),
            4 => (90, 30),
            5 => (120, 31),
            6 => (151, 30),
            7 => (181, 31),
            8 => (212, 31),
            9 => (243, 30),
            10 => (273, 31),
            11 => (304, 30),
            12 => (334, 31),
            _ => return Err(ErrorKind::DateTime.into()),
        };

        if day > mdays || day == 0 {
            return Err(ErrorKind::DateTime.into());
        }

        ydays += day as u16 - 1;

        if is_leap_year && month > 2 {
            ydays += 1;
        }

        let days = (year - 1970) as u64 * 365 + leap_years as u64 + ydays as u64;
        let time = seconds as u64 + (minutes as u64 * 60) + (hour as u64 * 3600);
        let unix_duration = Duration::from_secs(time + days * 86400);

        if unix_duration > MAX_UNIX_DURATION {
            return Err(ErrorKind::DateTime.into());
        }

        Ok(Self {
            year,
            month,
            day,
            hour,
            minutes,
            seconds,
            unix_duration,
        })
    }

    /// Compute a [`DateTime`] from the given [`Duration`] since the `UNIX_EPOCH`.
    ///
    /// Returns `None` if the value is outside the supported date range.
    pub fn from_unix_duration(unix_duration: Duration) -> Result<Self> {
        if unix_duration > MAX_UNIX_DURATION {
            return Err(ErrorKind::DateTime.into());
        }

        let secs_since_epoch = unix_duration.as_secs();

        /// 2000-03-01 (mod 400 year, immediately after Feb 29)
        const LEAPOCH: i64 = 11017;
        const DAYS_PER_400Y: i64 = 365 * 400 + 97;
        const DAYS_PER_100Y: i64 = 365 * 100 + 24;
        const DAYS_PER_4Y: i64 = 365 * 4 + 1;

        let days = (secs_since_epoch / 86400) as i64 - LEAPOCH;
        let secs_of_day = secs_since_epoch % 86400;

        let mut qc_cycles = days / DAYS_PER_400Y;
        let mut remdays = days % DAYS_PER_400Y;

        if remdays < 0 {
            remdays += DAYS_PER_400Y;
            qc_cycles -= 1;
        }

        let mut c_cycles = remdays / DAYS_PER_100Y;
        if c_cycles == 4 {
            c_cycles -= 1;
        }
        remdays -= c_cycles * DAYS_PER_100Y;

        let mut q_cycles = remdays / DAYS_PER_4Y;
        if q_cycles == 25 {
            q_cycles -= 1;
        }
        remdays -= q_cycles * DAYS_PER_4Y;

        let mut remyears = remdays / 365;
        if remyears == 4 {
            remyears -= 1;
        }
        remdays -= remyears * 365;

        let mut year = 2000 + remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

        let months = [31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29];
        let mut mon = 0;
        for mon_len in months.iter() {
            mon += 1;
            if remdays < *mon_len {
                break;
            }
            remdays -= *mon_len;
        }
        let mday = remdays + 1;
        let mon = if mon + 2 > 12 {
            year += 1;
            mon - 10
        } else {
            mon + 2
        };

        let second = secs_of_day % 60;
        let mins_of_day = secs_of_day / 60;
        let minute = mins_of_day % 60;
        let hour = mins_of_day / 60;

        Self::new(
            year as u16,
            mon,
            mday as u8,
            hour as u8,
            minute as u8,
            second as u8,
        )
    }

    /// Get the year.
    pub fn year(&self) -> u16 {
        self.year
    }

    /// Get the month.
    pub fn month(&self) -> u8 {
        self.month
    }

    /// Get the day.
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Get the hour.
    pub fn hour(&self) -> u8 {
        self.hour
    }

    /// Get the minutes.
    pub fn minutes(&self) -> u8 {
        self.minutes
    }

    /// Get the seconds.
    pub fn seconds(&self) -> u8 {
        self.seconds
    }

    /// Compute [`Duration`] since `UNIX_EPOCH` from the given calendar date.
    pub fn unix_duration(&self) -> Duration {
        self.unix_duration
    }

    /// Instantiate from [`SystemTime`].
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn from_system_time(time: SystemTime) -> Result<Self> {
        time.duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorKind::DateTime.into())
            .and_then(Self::from_unix_duration)
    }

    /// Convert to [`SystemTime`].
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn to_system_time(&self) -> SystemTime {
        UNIX_EPOCH + self.unix_duration()
    }
}

impl FromStr for DateTime {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match *s.as_bytes() {
            [year1, year2, year3, year4, b'-', month1, month2, b'-', day1, day2, b'T', hour1, hour2, b':', min1, min2, b':', sec1, sec2, b'Z'] =>
            {
                let tag = Tag::GeneralizedTime;
                let year = decode_decimal(tag, year1, year2).map_err(|_| ErrorKind::DateTime)?
                    as u16
                    * 100
                    + decode_decimal(tag, year3, year4).map_err(|_| ErrorKind::DateTime)? as u16;
                let month = decode_decimal(tag, month1, month2).map_err(|_| ErrorKind::DateTime)?;
                let day = decode_decimal(tag, day1, day2).map_err(|_| ErrorKind::DateTime)?;
                let hour = decode_decimal(tag, hour1, hour2).map_err(|_| ErrorKind::DateTime)?;
                let minutes = decode_decimal(tag, min1, min2).map_err(|_| ErrorKind::DateTime)?;
                let seconds = decode_decimal(tag, sec1, sec2).map_err(|_| ErrorKind::DateTime)?;
                Self::new(year, month, day, hour, minutes, seconds)
            }
            _ => Err(ErrorKind::DateTime.into()),
        }
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minutes, self.seconds
        )
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<DateTime> for SystemTime {
    fn from(time: DateTime) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl From<&DateTime> for SystemTime {
    fn from(time: &DateTime) -> SystemTime {
        time.to_system_time()
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<SystemTime> for DateTime {
    type Error = Error;

    fn try_from(time: SystemTime) -> Result<DateTime> {
        DateTime::from_system_time(time)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl TryFrom<&SystemTime> for DateTime {
    type Error = Error;

    fn try_from(time: &SystemTime) -> Result<DateTime> {
        DateTime::from_system_time(*time)
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<DateTime> for PrimitiveDateTime {
    type Error = Error;

    fn try_from(time: DateTime) -> Result<PrimitiveDateTime> {
        let month = (time.month() as u8).try_into()?;
        let date = time::Date::from_calendar_date(time.year() as i32, month, time.day())?;
        let time = time::Time::from_hms(time.hour(), time.minutes(), time.seconds())?;

        Ok(PrimitiveDateTime::new(date, time))
    }
}

#[cfg(feature = "time")]
#[cfg_attr(docsrs, doc(cfg(feature = "time")))]
impl TryFrom<PrimitiveDateTime> for DateTime {
    type Error = Error;

    fn try_from(time: PrimitiveDateTime) -> Result<DateTime> {
        DateTime::new(
            time.year() as u16,
            time.month().into(),
            time.day(),
            time.hour(),
            time.minute(),
            time.second(),
        )
    }
}

/// Decode 2-digit decimal value
pub(crate) fn decode_decimal(tag: Tag, hi: u8, lo: u8) -> Result<u8> {
    if (b'0'..=b'9').contains(&hi) && (b'0'..=b'9').contains(&lo) {
        Ok((hi - b'0') * 10 + (lo - b'0'))
    } else {
        Err(tag.value_error())
    }
}

/// Encode 2-digit decimal value
pub(crate) fn encode_decimal(encoder: &mut Encoder<'_>, tag: Tag, value: u8) -> Result<()> {
    let hi_val = value / 10;

    if hi_val >= 10 {
        return Err(tag.value_error());
    }

    encoder.byte(hi_val + b'0')?;
    encoder.byte((value % 10) + b'0')
}

#[cfg(test)]
mod tests {
    use super::DateTime;

    /// Ensure a day is OK
    fn is_date_valid(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> bool {
        DateTime::new(year, month, day, hour, minute, second).is_ok()
    }

    #[test]
    fn feb_leap_year_handling() {
        assert!(is_date_valid(2000, 2, 29, 0, 0, 0));
        assert!(!is_date_valid(2001, 2, 29, 0, 0, 0));
        assert!(!is_date_valid(2100, 2, 29, 0, 0, 0));
    }

    #[test]
    fn from_str() {
        let datetime = "2001-01-02T12:13:14Z".parse::<DateTime>().unwrap();
        assert_eq!(datetime.year(), 2001);
        assert_eq!(datetime.month(), 1);
        assert_eq!(datetime.day(), 2);
        assert_eq!(datetime.hour(), 12);
        assert_eq!(datetime.minutes(), 13);
        assert_eq!(datetime.seconds(), 14);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn display() {
        use alloc::string::ToString;
        let datetime = DateTime::new(2001, 01, 02, 12, 13, 14).unwrap();
        assert_eq!(&datetime.to_string(), "2001-01-02T12:13:14Z");
    }
}
