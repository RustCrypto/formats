use core::str::FromStr;
use core::time::Duration;
use der::{
    DateTime, DecodeValue, EncodeValue, ErrorKind, FixedTag, Header, Length, Reader, Result, Tag,
    Writer, asn1::GeneralizedTime,
};

/// ASN.1 `GeneralizedTime` type.
///
/// This type implements the validity requirements specified in
/// X.690 DER encoding of GeneralizedTime:
///
/// > 11.7.1 - The encoding shall terminate with a "Z"
/// > 11.7.2 - The seconds element shall always be present.
/// > 11.7.3 - The fractional-seconds elements, if present, shall omit all
/// >          trailing zeros; if the elements correspond to 0, they shall be wholly
/// >          omitted, and the decimal point element also shall be omitted
/// > 11.7.4 - The decimal point element, if present, shall be the point option ".".
/// > 11.7.5 - Midnight (GMT) shall be represented in the form `YYYYMMDD000000Z`
/// >          where `YYYYMMDD` represents the day following the midnight in question
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct GeneralizedTimeNanos {
    datetime: DateTime,

    /// Nanoseconds (0-999 999 999)
    nanoseconds: u32,
}

impl GeneralizedTimeNanos {
    /// Length of an RFC 5280-flavored ASN.1 DER-encoded [`GeneralizedTimeNanos`].
    const MIN_LENGTH: usize = 15;

    /// Maximum length of a GeneralizedTime containing nanoseconds.
    const MAX_LENGTH: usize = Self::MIN_LENGTH + 10;

    /// Get the duration of this timestamp since `UNIX_EPOCH`.
    pub fn to_unix_duration(&self) -> Duration {
        self.datetime.unix_duration() + Duration::from_nanos(u64::from(self.nanoseconds))
    }

    /// Create a new [`GeneralizedTimeNanos`] given a [`Duration`] since
    /// `UNIX_EPOCH` (a.k.a. "Unix time")
    pub fn from_unix_duration(unix_duration: Duration) -> Result<Self> {
        let datetime =
            DateTime::from_unix_duration(unix_duration).map_err(|_| Self::TAG.value_error())?;

        Ok(GeneralizedTimeNanos {
            datetime,
            nanoseconds: unix_duration.subsec_nanos(),
        })
    }
}

impl From<GeneralizedTime> for GeneralizedTimeNanos {
    fn from(time: GeneralizedTime) -> Self {
        Self {
            datetime: time.to_date_time(),
            nanoseconds: 0,
        }
    }
}

/// Decode 2-digit decimal value
#[allow(clippy::arithmetic_side_effects)]
fn decode_decimal(tag: Tag, hi: u8, lo: u8) -> Result<u8> {
    if hi.is_ascii_digit() && lo.is_ascii_digit() {
        Ok((hi - b'0') * 10 + (lo - b'0'))
    } else {
        Err(tag.value_error().into())
    }
}

/// Encode 2-digit decimal value
fn encode_decimal<W>(writer: &mut W, tag: Tag, value: u8) -> Result<()>
where
    W: Writer + ?Sized,
{
    let hi_val = value / 10;

    if hi_val >= 10 {
        return Err(tag.value_error().into());
    }

    writer.write_byte(b'0'.checked_add(hi_val).ok_or(ErrorKind::Overflow)?)?;
    writer.write_byte(b'0'.checked_add(value % 10).ok_or(ErrorKind::Overflow)?)
}

/// Decode up to 9 digits of fractional seconds, returns them as nanoseconds.
///
/// Assumes DER encoding rules, so no trailing zeroes.
fn decode_fractional_secs(tag: Tag, fract: &[u8]) -> Result<u32> {
    // An empty fractional should be checked for by the caller, and we only
    // support up to 9 digits (for nanoseconds accuracy).
    if fract.is_empty() || fract.len() > 9 {
        return Err(tag.value_error().into());
    }

    // The fractional seconds should not containing trailing zeros according
    // to DER encoding rules.
    if fract.last() == Some(&b'0') {
        return Err(tag.value_error().into());
    }

    // We're going to use u32::from_str, which accepts a leading + sign.
    // So make sure the leading digit is not a + but a proper digit.
    if !fract[0].is_ascii_digit() {
        return Err(tag.value_error().into());
    }

    // Decode the number. Use u32::from_ascii when it stabilizes, so we don't
    // pay the unnecessary cost of utf8 checking.
    let fract_str = core::str::from_utf8(fract).map_err(|_| tag.value_error())?;
    let fract_num = u32::from_str(fract_str).map_err(|_| tag.value_error())?;

    // Multiply the number to turn it into a nanosecond figure.
    let out = fract_num * 10_u32.pow(9 - u32::try_from(fract.len())?);

    Ok(out)
}

fn for_each_digits_without_trailing_zeroes<F>(mut nanoseconds: u32, mut f: F) -> Result<()>
where
    F: FnMut(u8) -> Result<()>,
{
    let mut idx = 100_000_000;
    while nanoseconds != 0 && idx != 0 {
        let cur_val = u8::try_from((nanoseconds / idx) % 10).map_err(|_| ErrorKind::Overflow)?;
        nanoseconds -= u32::from(cur_val) * idx;
        idx /= 10;
        f(cur_val)?
    }
    Ok(())
}

/// Encodes the given nanoseconds as fractional secs, discarding trailing
/// zeroes.
fn encode_fractional_secs<W>(writer: &mut W, tag: Tag, nanoseconds: u32) -> Result<()>
where
    W: Writer + ?Sized,
{
    // We should never have more than 999_999_999 nanoseconds in a second.
    if nanoseconds >= 1_000_000_000 {
        return Err(tag.value_error().into());
    }

    // if u32::format_into ever gets stabilized, this can be better written as
    //
    // ```
    // let mut buf = NumBuffer::new();
    // let s = value.format_into(&mut buf);
    // s.trim_end_matches('0');
    // writer.write(s.as_bytes())?;
    // ```
    //
    // This would benefit from using the standard library implementation of
    // formatting number, which is much more optimized, using LUTs to avoid a
    // lot of the work and handling multiple digits simultaneously.
    for_each_digits_without_trailing_zeroes(nanoseconds, |cur_val| {
        writer.write_byte(b'0'.checked_add(cur_val).ok_or(ErrorKind::Overflow)?)
    })?;
    Ok(())
}

/// Creates a [`GeneralizedTimeNanos`] from its individual, ascii
/// encoded components.
#[allow(clippy::too_many_arguments, reason = "Simple helper function")]
fn decode_from_values(
    year: (u8, u8, u8, u8),
    month: (u8, u8),
    day: (u8, u8),
    hour: (u8, u8),
    min: (u8, u8),
    sec: (u8, u8),
    fract: Option<&[u8]>,
) -> Result<GeneralizedTimeNanos> {
    let year = u16::from(decode_decimal(GeneralizedTimeNanos::TAG, year.0, year.1)?)
        .checked_mul(100)
        .and_then(|y| {
            y.checked_add(
                decode_decimal(GeneralizedTimeNanos::TAG, year.2, year.3)
                    .ok()?
                    .into(),
            )
        })
        .ok_or(ErrorKind::DateTime)?;
    let month = decode_decimal(GeneralizedTimeNanos::TAG, month.0, month.1)?;
    let day = decode_decimal(GeneralizedTimeNanos::TAG, day.0, day.1)?;
    let hour = decode_decimal(GeneralizedTimeNanos::TAG, hour.0, hour.1)?;
    let minute = decode_decimal(GeneralizedTimeNanos::TAG, min.0, min.1)?;
    let second = decode_decimal(GeneralizedTimeNanos::TAG, sec.0, sec.1)?;

    let nanoseconds = if let Some(fract) = fract {
        decode_fractional_secs(GeneralizedTimeNanos::TAG, fract)?
    } else {
        0
    };

    let datetime = DateTime::new(year, month, day, hour, minute, second)
        .map_err(|_| GeneralizedTimeNanos::TAG.value_error())?;

    Ok(GeneralizedTimeNanos {
        datetime,
        nanoseconds,
    })
}

impl<'a> DecodeValue<'a> for GeneralizedTimeNanos {
    type Error = der::Error;

    #[rustfmt::skip] // Keep the match readable on a single line.
    fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> Result<Self> {
        let len = usize::try_from(header.length())?;
        if !(Self::MIN_LENGTH..=Self::MAX_LENGTH).contains(&len) {
            return Err(Self::TAG.value_error().into());
        }

        let mut bytes = [0u8; Self::MAX_LENGTH];
        let data = reader.read_into(&mut bytes[..len])?;

        match data {
            // No nanoseconds
            [y1, y2, y3, y4, mon1, mon2, day1, day2, hour1, hour2, min1, min2, sec1, sec2, b'Z'] =>
                decode_from_values((*y1, *y2, *y3, *y4), (*mon1, *mon2), (*day1, *day2),
                    (*hour1, *hour2), (*min1, *min2), (*sec1, *sec2), None),
            // With nanoseconds
            [y1, y2, y3, y4, mon1, mon2, day1, day2, hour1, hour2, min1, min2, sec1, sec2, b'.', fract @ .., b'Z'] =>
                decode_from_values((*y1, *y2, *y3, *y4), (*mon1, *mon2), (*day1, *day2),
                    (*hour1, *hour2), (*min1, *min2), (*sec1, *sec2), Some(fract)),
            _ => Err(Self::TAG.value_error().into()),
        }
    }
}

impl EncodeValue for GeneralizedTimeNanos {
    fn value_len(&self) -> Result<Length> {
        let mut len = Self::MIN_LENGTH;
        if self.nanoseconds != 0 {
            // Count the number of digits we'll encode.
            for_each_digits_without_trailing_zeroes(self.nanoseconds, |_| {
                len += 1;
                Ok(())
            })?;
            // + 1 for the decimal separator.
            len += 1;
        }
        Length::try_from(len)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> Result<()> {
        let year_hi = u8::try_from(self.datetime.year() / 100)?;
        let year_lo = u8::try_from(self.datetime.year() % 100)?;

        encode_decimal(writer, Self::TAG, year_hi)?;
        encode_decimal(writer, Self::TAG, year_lo)?;
        encode_decimal(writer, Self::TAG, self.datetime.month())?;
        encode_decimal(writer, Self::TAG, self.datetime.day())?;
        encode_decimal(writer, Self::TAG, self.datetime.hour())?;
        encode_decimal(writer, Self::TAG, self.datetime.minutes())?;
        encode_decimal(writer, Self::TAG, self.datetime.seconds())?;
        if self.nanoseconds != 0 {
            writer.write_byte(b'.')?;
            encode_fractional_secs(writer, Self::TAG, self.nanoseconds)?;
        }
        writer.write_byte(b'Z')
    }
}

impl FixedTag for GeneralizedTimeNanos {
    const TAG: Tag = Tag::GeneralizedTime;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::GeneralizedTimeNanos;
    use der::{Decode, Encode, SliceWriter};
    use hex_literal::hex;

    fn round_trip(der: &[u8], expected_timestamp: u64, expected_nanos: u32) {
        let utc_time = GeneralizedTimeNanos::from_der(der).unwrap();
        assert_eq!(utc_time.to_unix_duration().as_secs(), expected_timestamp);
        assert_eq!(utc_time.to_unix_duration().subsec_nanos(), expected_nanos);

        let mut buf = [0u8; 128];
        let mut encoder = SliceWriter::new(&mut buf);
        utc_time.encode(&mut encoder).unwrap();
        assert_eq!(der, encoder.finish().unwrap());
    }

    #[test]
    fn round_trip_normal() {
        let example_bytes = hex!("18 0f 31 39 39 31 30 35 30 36 32 33 34 35 34 30 5a");
        round_trip(&example_bytes, 673573540, 0);
    }

    #[test]
    fn round_trip_nanoseconds_100_000_000() {
        let example_bytes = hex!("18 11 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 5A");
        round_trip(&example_bytes, 1728312610, 100_000_000);
    }

    #[test]
    fn round_trip_nanoseconds_120_000_000() {
        let example_bytes = hex!("18 12 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 5A");
        round_trip(&example_bytes, 1728312610, 120_000_000);
    }

    #[test]
    fn round_trip_nanoseconds_123_000_000() {
        let example_bytes = hex!("18 13 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 5A");
        round_trip(&example_bytes, 1728312610, 123_000_000);
    }

    #[test]
    fn round_trip_nanoseconds_123_400_000() {
        let example_bytes =
            hex!("18 14 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 5A");
        round_trip(&example_bytes, 1728312610, 123_400_000);
    }

    #[test]
    fn round_trip_nanoseconds_123_450_000() {
        let example_bytes =
            hex!("18 15 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 35 5A");
        round_trip(&example_bytes, 1728312610, 123_450_000);
    }

    #[test]
    fn round_trip_nanoseconds_123_456_000() {
        let example_bytes =
            hex!("18 16 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 35 36 5A");
        round_trip(&example_bytes, 1728312610, 123_456_000);
    }

    #[test]
    fn round_trip_nanoseconds_123_456_700() {
        let example_bytes =
            hex!("18 17 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 35 36 37 5A");
        round_trip(&example_bytes, 1728312610, 123_456_700);
    }

    #[test]
    fn round_trip_nanoseconds_123_456_780() {
        let example_bytes =
            hex!("18 18 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 35 36 37 38 5A");
        round_trip(&example_bytes, 1728312610, 123_456_780);
    }

    #[test]
    fn round_trip_nanoseconds_123_456_789() {
        let example_bytes = hex!(
            "18 19 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 31 32 33 34 35 36 37 38 39 5A"
        );
        round_trip(&example_bytes, 1728312610, 123_456_789);
    }

    #[test]
    fn round_trip_nanoseconds_000_000_005() {
        let example_bytes = hex!(
            "18 19 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 30 30 30 30 30 30 30 30 35 5A"
        );
        round_trip(&example_bytes, 1728312610, 5);
    }

    #[test]
    fn invalid_generalized_time_delimiter_no_subsec() {
        let example_bytes = hex!("18 10 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 5A");
        let err = GeneralizedTimeNanos::from_der(&example_bytes).unwrap_err();
        assert_eq!(
            err.kind(),
            der::ErrorKind::Value {
                tag: der::Tag::GeneralizedTime
            }
        );
    }

    #[test]
    fn invalid_generalized_time_trailing_zeroes() {
        let example_bytes = hex!(
            "18 1A 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 33 32 30 30 30 30 30 30 30 30 5A"
        );
        let err = GeneralizedTimeNanos::from_der(&example_bytes).unwrap_err();
        assert_eq!(
            err.kind(),
            der::ErrorKind::Value {
                tag: der::Tag::GeneralizedTime
            }
        );
    }

    #[test]
    fn invalid_generalized_time_too_long() {
        let example_bytes = hex!(
            "18 1A 32 30 32 34 31 30 30 37 31 34 35 30 31 30 2E 30 30 30 30 30 30 30 30 30 35 5A"
        );
        let err = GeneralizedTimeNanos::from_der(&example_bytes).unwrap_err();
        assert_eq!(
            err.kind(),
            der::ErrorKind::Value {
                tag: der::Tag::GeneralizedTime
            }
        );
    }
}
