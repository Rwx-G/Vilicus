//! Time as the spine conventions fix it: UTC integer milliseconds in storage, RFC 3339 at the
//! edges.

use core::fmt;
use core::str::FromStr;

const MILLIS_PER_SECOND: i64 = 1_000;
const MILLIS_PER_MINUTE: i64 = 60 * MILLIS_PER_SECOND;
const MILLIS_PER_DAY: i64 = 24 * 60 * MILLIS_PER_MINUTE;

/// An instant in UTC, as whole milliseconds since the Unix epoch.
///
/// The range is the one RFC 3339 can write, years 0000 to 9999 of the proleptic Gregorian
/// calendar; a value outside it is refused, never clamped. Storage keeps [`as_millis`]; the
/// edges, serialization included, use the RFC 3339 text that [`Display`] writes and
/// [`parse_rfc3339`] reads. There are no leap seconds: a day is always 86 400 000 ms, as in Unix
/// time.
///
/// ```
/// use vilicus_types::UtcMillis;
///
/// let instant = UtcMillis::parse_rfc3339("1996-12-19T16:39:57-08:00")?;
/// assert_eq!(instant.as_millis(), 851_042_397_000);
/// assert_eq!(instant.to_string(), "1996-12-20T00:39:57.000Z");
/// # Ok::<(), vilicus_types::TimeError>(())
/// ```
///
/// [`as_millis`]: UtcMillis::as_millis
/// [`Display`]: core::fmt::Display
/// [`parse_rfc3339`]: UtcMillis::parse_rfc3339
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UtcMillis(i64);

/// A refused instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeError {
    /// The instant lies outside years 0000 to 9999.
    OutOfRange,
    /// The text is not an RFC 3339 `date-time`.
    Malformed,
    /// A date or time field is outside its range (month 13, February 30, hour 24, offset 24:00).
    InvalidField,
    /// Second 60 at 23:59 UTC: a leap second cannot be represented in Unix time.
    LeapSecond,
    /// The fraction has a non-zero digit below the millisecond, which would be lost.
    SubMillisecond,
}

impl fmt::Display for TimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutOfRange => "instant outside years 0000 to 9999",
            Self::Malformed => "not an RFC 3339 date-time",
            Self::InvalidField => "date or time field out of range",
            Self::LeapSecond => "leap second not representable",
            Self::SubMillisecond => "precision below the millisecond",
        })
    }
}

impl std::error::Error for TimeError {}

const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap_year(year) => 29,
        _ => 28,
    }
}

/// True for a calendar date in the RFC 3339 `full-date` form, `YYYY-MM-DD`, of the proleptic
/// Gregorian calendar in the years [`UtcMillis`] covers, 0000 to 9999: exactly ten ASCII
/// characters, a month from 01 to 12 and a day that exists in that month. Anything else is
/// refused, never normalized, so one date has one text (`2026-1-05`, `2026-02-29` and a trailing
/// time are refused). A `const` check, so the storage layer and a declaration read the same rule.
///
/// ```
/// use vilicus_types::is_full_date;
///
/// assert!(is_full_date("2024-02-29"));
/// assert!(!is_full_date("2026-02-29"));
/// assert!(!is_full_date("2026-10-18T00:00:00Z"));
/// ```
pub const fn is_full_date(text: &str) -> bool {
    const DIGITS: [usize; 8] = [0, 1, 2, 3, 5, 6, 8, 9];
    let bytes = text.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let mut index = 0;
    while index < DIGITS.len() {
        if !bytes[DIGITS[index]].is_ascii_digit() {
            return false;
        }
        index += 1;
    }
    let year = number(bytes, 0, 4);
    let month = number(bytes, 5, 2);
    let day = number(bytes, 8, 2);
    matches!(month, 1..=12) && day > 0 && day <= days_in_month(year, month)
}

/// The decimal number of the `count` ASCII digits of `bytes` from `start`.
const fn number(bytes: &[u8], start: usize, count: usize) -> i64 {
    let mut value = 0;
    let mut index = start;
    while index < start + count {
        value = value * 10 + (bytes[index] - b'0') as i64;
        index += 1;
    }
    value
}

/// Days from 1970-01-01 to the given date of the proleptic Gregorian calendar; the algorithm of
/// Howard Hinnant's `days_from_civil`, over 400-year eras of 146 097 days that start in March.
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = (if year >= 0 { year } else { year - 399 }) / 400;
    let year_of_era = year - era * 400;
    let month_from_march = (month + 9) % 12;
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`]: (year, month, day) of a day count from 1970-01-01.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = (if days >= 0 { days } else { days - 146_096 }) / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

impl UtcMillis {
    /// The earliest instant: 0000-01-01T00:00:00.000Z.
    pub const MIN: Self = Self(days_from_civil(0, 1, 1) * MILLIS_PER_DAY);

    /// The latest instant: 9999-12-31T23:59:59.999Z.
    pub const MAX: Self = Self(days_from_civil(10_000, 1, 1) * MILLIS_PER_DAY - 1);

    /// The Unix epoch, 1970-01-01T00:00:00.000Z.
    pub const UNIX_EPOCH: Self = Self(0);

    /// The instant `millis` milliseconds after the Unix epoch (before it when negative), as
    /// storage holds it.
    pub const fn from_millis(millis: i64) -> Result<Self, TimeError> {
        if millis < Self::MIN.0 || millis > Self::MAX.0 {
            return Err(TimeError::OutOfRange);
        }
        Ok(Self(millis))
    }

    /// Milliseconds since the Unix epoch, the stored form.
    pub const fn as_millis(self) -> i64 {
        self.0
    }

    /// Reads an RFC 3339 `date-time` (section 5.6): `T` or `t` between date and time, an optional
    /// fraction of any length, and `Z`, `z` or a numeric offset, which is applied to give UTC
    /// (`-00:00` is UTC). Refused: a field out of range, second 60 (a leap second at 23:59 UTC,
    /// an invalid field at any other time), a non-zero digit below the millisecond, and an instant
    /// outside [`MIN`](Self::MIN) and [`MAX`](Self::MAX) once the offset is applied.
    pub fn parse_rfc3339(text: &str) -> Result<Self, TimeError> {
        let mut reader = Reader {
            bytes: text.as_bytes(),
            position: 0,
        };
        let year = reader.digits(4)?;
        reader.expect(b"-")?;
        let month = reader.digits(2)?;
        reader.expect(b"-")?;
        let day = reader.digits(2)?;
        reader.expect(b"Tt")?;
        let hour = reader.digits(2)?;
        reader.expect(b":")?;
        let minute = reader.digits(2)?;
        reader.expect(b":")?;
        let second = reader.digits(2)?;
        let millis = reader.fraction_millis()?;
        let offset_minutes = reader.offset_minutes()?;
        if reader.position != reader.bytes.len() {
            return Err(TimeError::Malformed);
        }

        if !(1..=12).contains(&month)
            || !(1..=days_in_month(year, month)).contains(&day)
            || hour > 23
            || minute > 59
        {
            return Err(TimeError::InvalidField);
        }
        if second > 60 {
            return Err(TimeError::InvalidField);
        }

        let local = days_from_civil(year, month, day) * MILLIS_PER_DAY
            + (hour * 60 + minute) * MILLIS_PER_MINUTE
            + second.min(59) * MILLIS_PER_SECOND
            + millis;
        let utc = local - offset_minutes * MILLIS_PER_MINUTE;
        if second == 60 {
            // A leap second exists only as the last second of a UTC day, 23:59:60.
            let last_utc_minute =
                utc.rem_euclid(MILLIS_PER_DAY) / MILLIS_PER_MINUTE == 23 * 60 + 59;
            return Err(if last_utc_minute {
                TimeError::LeapSecond
            } else {
                TimeError::InvalidField
            });
        }
        Self::from_millis(utc)
    }
}

/// A cursor over the ASCII bytes of an RFC 3339 text.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn next_digit(&mut self) -> Option<i64> {
        let byte = *self.bytes.get(self.position)?;
        byte.is_ascii_digit().then(|| {
            self.position += 1;
            i64::from(byte - b'0')
        })
    }

    fn digits(&mut self, count: usize) -> Result<i64, TimeError> {
        (0..count).try_fold(0, |value, _| {
            self.next_digit()
                .map(|digit| value * 10 + digit)
                .ok_or(TimeError::Malformed)
        })
    }

    fn expect(&mut self, accepted: &[u8]) -> Result<u8, TimeError> {
        match self.bytes.get(self.position) {
            Some(byte) if accepted.contains(byte) => {
                self.position += 1;
                Ok(*byte)
            }
            _ => Err(TimeError::Malformed),
        }
    }

    /// `time-secfrac`, read as milliseconds: three digits at most carry value, any further digit
    /// must be zero.
    fn fraction_millis(&mut self) -> Result<i64, TimeError> {
        if self.expect(b".").is_err() {
            return Ok(0);
        }
        let mut millis = 0;
        let mut count: usize = 0;
        let mut below_millisecond = false;
        while let Some(digit) = self.next_digit() {
            if count < 3 {
                millis = millis * 10 + digit;
            } else if digit != 0 {
                below_millisecond = true;
            }
            count += 1;
        }
        if count == 0 {
            return Err(TimeError::Malformed);
        }
        if below_millisecond {
            return Err(TimeError::SubMillisecond);
        }
        Ok(match count {
            1 => millis * 100,
            2 => millis * 10,
            _ => millis,
        })
    }

    /// `time-offset`, as signed minutes east of UTC.
    fn offset_minutes(&mut self) -> Result<i64, TimeError> {
        let sign = match self.expect(b"Zz+-")? {
            b'+' => 1,
            b'-' => -1,
            _ => return Ok(0),
        };
        let hours = self.digits(2)?;
        self.expect(b":")?;
        let minutes = self.digits(2)?;
        if hours > 23 || minutes > 59 {
            return Err(TimeError::InvalidField);
        }
        Ok(sign * (hours * 60 + minutes))
    }
}

impl fmt::Display for UtcMillis {
    /// Writes the instant as `YYYY-MM-DDTHH:MM:SS.mmmZ`: always UTC, always three fraction digits,
    /// so one instant has one text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(MILLIS_PER_DAY);
        let in_day = self.0.rem_euclid(MILLIS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let hour = in_day / (60 * MILLIS_PER_MINUTE);
        let minute = in_day / MILLIS_PER_MINUTE % 60;
        let second = in_day / MILLIS_PER_SECOND % 60;
        let millis = in_day % MILLIS_PER_SECOND;
        write!(
            formatter,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
        )
    }
}

impl fmt::Debug for UtcMillis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "UtcMillis({self})")
    }
}

impl FromStr for UtcMillis {
    type Err = TimeError;

    fn from_str(text: &str) -> Result<Self, TimeError> {
        Self::parse_rfc3339(text)
    }
}

impl serde::Serialize for UtcMillis {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for UtcMillis {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Rfc3339Visitor;

        impl serde::de::Visitor<'_> for Rfc3339Visitor {
            type Value = UtcMillis;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an RFC 3339 date-time between years 0000 and 9999")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<UtcMillis, E> {
                UtcMillis::parse_rfc3339(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Rfc3339Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{from_str, to_json};

    fn parse(text: &str) -> Result<i64, TimeError> {
        UtcMillis::parse_rfc3339(text).map(UtcMillis::as_millis)
    }

    fn render(millis: i64) -> String {
        UtcMillis::from_millis(millis)
            .expect("in range")
            .to_string()
    }

    #[test]
    fn rfc3339_section_5_8_examples() {
        assert_eq!(parse("1985-04-12T23:20:50.52Z"), Ok(482_196_050_520));
        assert_eq!(parse("1996-12-19T16:39:57-08:00"), Ok(851_042_397_000));
        assert_eq!(
            parse("1937-01-01T12:00:27.87+00:20").map(render).as_deref(),
            Ok("1937-01-01T11:40:27.870Z")
        );
        // The two leap-second examples are valid RFC 3339 but have no Unix time.
        assert_eq!(parse("1990-12-31T23:59:60Z"), Err(TimeError::LeapSecond));
        assert_eq!(
            parse("1990-12-31T15:59:60-08:00"),
            Err(TimeError::LeapSecond)
        );
        // Second 60 anywhere but at 23:59 UTC is no leap second, only an invalid field.
        assert_eq!(parse("1990-12-31T12:00:60Z"), Err(TimeError::InvalidField));
        assert_eq!(
            parse("1990-12-31T23:59:60-08:00"),
            Err(TimeError::InvalidField)
        );
        assert_eq!(
            parse("1990-12-31T23:59:60+00:00"),
            Err(TimeError::LeapSecond)
        );
    }

    #[test]
    fn known_instants() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(parse("2000-01-01T00:00:00Z"), Ok(946_684_800_000));
        assert_eq!(parse("2000-02-29T00:00:00Z"), Ok(951_782_400_000));
        assert_eq!(parse("1969-12-31T23:59:59.999Z"), Ok(-1));
        assert_eq!(render(-1), "1969-12-31T23:59:59.999Z");
        // RFC 9562 appendix A.6: the instant of its UUIDv7 example.
        assert_eq!(parse("2022-02-22T14:22:22.00-05:00"), Ok(0x017F_22E2_79B0));
    }

    #[test]
    fn range_is_years_0000_to_9999() {
        assert_eq!(UtcMillis::MIN.as_millis(), -62_167_219_200_000);
        assert_eq!(UtcMillis::MAX.as_millis(), 253_402_300_799_999);
        assert_eq!(UtcMillis::MIN.to_string(), "0000-01-01T00:00:00.000Z");
        assert_eq!(UtcMillis::MAX.to_string(), "9999-12-31T23:59:59.999Z");
        assert_eq!(
            UtcMillis::from_millis(UtcMillis::MIN.as_millis() - 1),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(
            UtcMillis::from_millis(UtcMillis::MAX.as_millis() + 1),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(UtcMillis::from_millis(i64::MIN), Err(TimeError::OutOfRange));
        assert_eq!(UtcMillis::from_millis(i64::MAX), Err(TimeError::OutOfRange));
        assert_eq!(
            parse("0000-01-01T00:00:00Z"),
            Ok(UtcMillis::MIN.as_millis())
        );
        assert_eq!(
            parse("9999-12-31T23:59:59.999Z"),
            Ok(UtcMillis::MAX.as_millis())
        );
        // An offset can carry a valid local text outside the range.
        assert_eq!(
            parse("0000-01-01T00:59:59+01:00"),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(
            parse("9999-12-31T23:59:59.999-00:01"),
            Err(TimeError::OutOfRange)
        );
        assert_eq!(parse("10000-01-01T00:00:00Z"), Err(TimeError::Malformed));
        assert_eq!(parse("-0001-01-01T00:00:00Z"), Err(TimeError::Malformed));
    }

    #[test]
    fn leap_years() {
        for leap in [
            "2000-02-29",
            "2024-02-29",
            "1600-02-29",
            "0000-02-29",
            "9996-02-29",
        ] {
            assert!(parse(&format!("{leap}T00:00:00Z")).is_ok(), "{leap}");
        }
        for common in ["1900-02-29", "2023-02-29", "2100-02-29", "9999-02-29"] {
            assert_eq!(
                parse(&format!("{common}T00:00:00Z")),
                Err(TimeError::InvalidField),
                "{common}"
            );
        }
        assert_eq!(parse("2024-02-30T00:00:00Z"), Err(TimeError::InvalidField));
    }

    #[test]
    fn year_boundaries() {
        let new_year = parse("2000-01-01T00:00:00Z").expect("valid");
        assert_eq!(render(new_year - 1), "1999-12-31T23:59:59.999Z");
        let leap_day_end = parse("2000-02-29T23:59:59.999Z").expect("valid");
        assert_eq!(render(leap_day_end + 1), "2000-03-01T00:00:00.000Z");
        assert_eq!(
            parse("2000-01-01T00:30:00+01:00").map(render).as_deref(),
            Ok("1999-12-31T23:30:00.000Z")
        );
        assert_eq!(
            parse("1999-12-31T23:30:00-01:00").map(render).as_deref(),
            Ok("2000-01-01T00:30:00.000Z")
        );
    }

    #[test]
    fn every_day_of_the_range_round_trips() {
        let first = UtcMillis::MIN.as_millis() / MILLIS_PER_DAY;
        let last = UtcMillis::MAX.as_millis().div_euclid(MILLIS_PER_DAY);
        let mut expected = (0, 1, 1);
        for days in first..=last {
            assert_eq!(civil_from_days(days), expected, "day {days}");
            assert_eq!(days_from_civil(expected.0, expected.1, expected.2), days);
            let (year, month, day) = expected;
            expected = if day < days_in_month(year, month) {
                (year, month, day + 1)
            } else if month < 12 {
                (year, month + 1, 1)
            } else {
                (year + 1, 1, 1)
            };
        }
        assert_eq!(expected, (10_000, 1, 1));
    }

    /// Every day of the range is a full date as `Display` writes it, and nothing else of that
    /// shape is: each month's day after its last, month 00 and 13, day 00.
    #[test]
    fn full_dates_are_the_days_of_the_range() {
        let first = UtcMillis::MIN.as_millis() / MILLIS_PER_DAY;
        let last = UtcMillis::MAX.as_millis().div_euclid(MILLIS_PER_DAY);
        for days in first..=last {
            let text = render(days * MILLIS_PER_DAY);
            assert!(is_full_date(&text[..10]), "{text}");
            let (year, month, _) = civil_from_days(days);
            let past_the_end =
                format!("{year:04}-{month:02}-{:02}", days_in_month(year, month) + 1);
            assert!(!is_full_date(&past_the_end), "{past_the_end}");
        }
        for text in [
            "",
            "2026-10-1",
            "2026-1-018",
            "2026-00-10",
            "2026-13-10",
            "2026-10-00",
            "2026-10-18 ",
            " 2026-10-18",
            "2026/10/18",
            "20261018",
            "+026-10-18",
            "-026-10-18",
            "2026-10-18T00:00:00Z",
            "\u{ff12}026-10-18",
            "1900-02-29",
            "2100-02-29",
        ] {
            assert!(!is_full_date(text), "{text:?}");
        }
        for text in ["0000-01-01", "0000-02-29", "2000-02-29", "9999-12-31"] {
            assert!(is_full_date(text), "{text}");
        }
    }

    #[test]
    fn rendering_parses_back() {
        let samples = [
            UtcMillis::MIN.as_millis(),
            -86_400_001,
            -1,
            0,
            1,
            482_196_050_520,
            UtcMillis::MAX.as_millis(),
        ];
        for millis in samples {
            let text = render(millis);
            assert_eq!(text.len(), "0000-01-01T00:00:00.000Z".len(), "{text}");
            assert_eq!(parse(&text), Ok(millis), "{text}");
        }
    }

    #[test]
    fn accepted_syntax() {
        let reference = parse("2026-10-18T12:34:56.789Z").expect("valid");
        for same in [
            "2026-10-18t12:34:56.789z",
            "2026-10-18T12:34:56.789000000Z",
            "2026-10-18T12:34:56.789+00:00",
            "2026-10-18T12:34:56.789-00:00",
            "2026-10-18T14:04:56.789+01:30",
            "2026-10-17T23:35:56.789-12:59",
        ] {
            assert_eq!(parse(same), Ok(reference), "{same}");
        }
        assert_eq!(parse("2026-10-18T12:34:56Z"), Ok(reference - 789));
        assert_eq!(parse("2026-10-18T12:34:56.7Z"), Ok(reference - 89));
    }

    #[test]
    fn refused_syntax() {
        for (text, error) in [
            ("", TimeError::Malformed),
            ("2026-10-18", TimeError::Malformed),
            ("2026-10-18 12:34:56Z", TimeError::Malformed),
            ("2026-10-18T12:34:56", TimeError::Malformed),
            ("2026-10-18T12:34Z", TimeError::Malformed),
            ("2026-10-18T12:34:56.Z", TimeError::Malformed),
            ("2026-10-18T12:34:56+0100", TimeError::Malformed),
            ("2026-10-18T12:34:56+01", TimeError::Malformed),
            ("2026-10-18T12:34:56ZZ", TimeError::Malformed),
            ("2026-1-18T12:34:56Z", TimeError::Malformed),
            ("+2026-10-18T12:34:56Z", TimeError::Malformed),
            ("\u{ff12}026-10-18T12:34:56Z", TimeError::Malformed),
            ("2026-10-18T12:34:56.1234Z", TimeError::SubMillisecond),
            ("2026-10-18T12:34:56.0000001Z", TimeError::SubMillisecond),
            ("2026-00-18T12:34:56Z", TimeError::InvalidField),
            ("2026-13-18T12:34:56Z", TimeError::InvalidField),
            ("2026-10-00T12:34:56Z", TimeError::InvalidField),
            ("2026-10-32T12:34:56Z", TimeError::InvalidField),
            ("2026-04-31T12:34:56Z", TimeError::InvalidField),
            ("2026-10-18T24:00:00Z", TimeError::InvalidField),
            ("2026-10-18T12:60:56Z", TimeError::InvalidField),
            ("2026-10-18T12:34:61Z", TimeError::InvalidField),
            ("2026-10-18T12:34:56+24:00", TimeError::InvalidField),
            ("2026-10-18T12:34:56+01:60", TimeError::InvalidField),
        ] {
            assert_eq!(parse(text), Err(error), "{text:?}");
        }
    }

    #[test]
    fn serialized_as_rfc3339_text() {
        let instant = UtcMillis::from_millis(482_196_050_520).expect("in range");
        assert_eq!(
            to_json(&instant).as_deref(),
            Ok("\"1985-04-12T23:20:50.520Z\"")
        );
        assert_eq!(
            from_str::<UtcMillis>("1985-04-12T23:20:50.52Z"),
            Ok(instant)
        );
        assert!(from_str::<UtcMillis>("1990-12-31T23:59:60Z").is_err());
        assert!(from_str::<UtcMillis>("482196050520").is_err());
    }
}
