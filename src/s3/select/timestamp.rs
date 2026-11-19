//! S3 Select's timestamps: Ion's, as its SQL has them (`` `2007-02-23T` ``,
//! `TO_TIMESTAMP`, `CAST(... AS TIMESTAMP)`), with their precision and
//! offset, and the arithmetic of `DATE_ADD`, `DATE_DIFF` and `EXTRACT`.

use std::cmp::Ordering;
use std::fmt::Write;

use super::SelectError;

/// How precisely a timestamp is known: what its text has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Precision {
    Year,
    Month,
    Day,
    Minute,
    Second,
    /// Seconds with this many digits of fraction (1 to 9).
    Fraction(u8),
}

/// A timestamp: its local date and time, at its offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanos: u32,
    /// Minutes east of UTC; `None` if unknown (`-00:00`, and every
    /// timestamp of only a date), which counts as UTC.
    pub offset: Option<i16>,
    pub precision: Precision,
}

/// A part of a timestamp, as `DATE_ADD`, `DATE_DIFF` and `EXTRACT` name
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    /// `EXTRACT`'s only.
    TimezoneHour,
    TimezoneMinute,
}

impl Part {
    pub fn parse(name: &str) -> Option<Part> {
        Some(match name.to_ascii_lowercase().as_str() {
            "year" => Part::Year,
            "month" => Part::Month,
            "day" => Part::Day,
            "hour" => Part::Hour,
            "minute" => Part::Minute,
            "second" => Part::Second,
            "timezone_hour" => Part::TimezoneHour,
            "timezone_minute" => Part::TimezoneMinute,
            _ => return None,
        })
    }
}

const NANOS: i128 = 1_000_000_000;
const DAY: i64 = 86_400;

/// Whether `year` is a leap year.
fn leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// How many days `month` of `year` has.
pub fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        2 if leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date `days` after 1970-01-01 (`civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn invalid(text: &str) -> SelectError {
    SelectError::new(
        "CastFailed",
        format!(
            "'{}' isn't a timestamp.",
            text.chars().take(64).collect::<String>()
        ),
    )
}

fn out_of_range() -> SelectError {
    SelectError::new(
        "EvaluatorInvalidArguments",
        "The timestamp is out of range: years go from 1 to 9999.",
    )
}

impl Timestamp {
    /// Reads Ion's text of a timestamp: `2007T`, `2007-02T`, `2007-02-23`
    /// (or with a `T`), `2007-02-23T12:14Z`, `2007-02-23T12:14:33.079-08:00`.
    /// An offset may be left off a time, as AWS's examples do: it's
    /// unknown then.
    pub fn parse(text: &str) -> Result<Timestamp, SelectError> {
        Self::parse_ion(text.trim()).ok_or_else(|| invalid(text))
    }

    fn parse_ion(text: &str) -> Option<Timestamp> {
        let b = text.as_bytes();
        let digits = |from: usize, n: usize| -> Option<u32> {
            let part = b.get(from..from + n)?;
            part.iter()
                .all(u8::is_ascii_digit)
                .then(|| std::str::from_utf8(part).ok()?.parse().ok())?
        };
        let mut t = Timestamp {
            year: digits(0, 4)? as i32,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            nanos: 0,
            offset: None,
            precision: Precision::Year,
        };
        if t.year < 1 {
            return None;
        }
        let rest = &text[4..];
        if rest == "T" {
            return Some(t);
        }
        if b.get(4) != Some(&b'-') {
            return None;
        }
        t.month = digits(5, 2)? as u8;
        if !(1..=12).contains(&t.month) {
            return None;
        }
        t.precision = Precision::Month;
        if &text[7..] == "T" {
            return Some(t);
        }
        if b.get(7) != Some(&b'-') {
            return None;
        }
        t.day = digits(8, 2)? as u8;
        if t.day < 1 || t.day > days_in_month(t.year, t.month) {
            return None;
        }
        t.precision = Precision::Day;
        match &text[10..] {
            "" | "T" => return Some(t),
            _ if b[10] != b'T' => return None,
            _ => {}
        }
        t.hour = digits(11, 2)? as u8;
        if b.get(13) != Some(&b':') {
            return None;
        }
        t.minute = digits(14, 2)? as u8;
        if t.hour > 23 || t.minute > 59 {
            return None;
        }
        t.precision = Precision::Minute;
        let mut at = 16;
        if b.get(at) == Some(&b':') {
            t.second = digits(17, 2)? as u8;
            if t.second > 59 {
                return None;
            }
            t.precision = Precision::Second;
            at = 19;
            if b.get(at) == Some(&b'.') {
                let n = b[at + 1..]
                    .iter()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                if n == 0 || n > 9 {
                    return None;
                }
                let fraction: u32 = text[at + 1..at + 1 + n].parse().ok()?;
                t.nanos = fraction * 10u32.pow(9 - n as u32);
                t.precision = Precision::Fraction(n as u8);
                at += 1 + n;
            }
        }
        t.offset = match &text[at..] {
            "" | "-00:00" => None,
            "Z" => Some(0),
            offset => {
                let sign = match offset.as_bytes().first()? {
                    b'+' => 1,
                    b'-' => -1,
                    _ => return None,
                };
                let ob = offset.as_bytes();
                if ob.len() != 6 || ob[3] != b':' {
                    return None;
                }
                let hours: i16 = offset[1..3].parse().ok()?;
                let minutes: i16 = offset[4..6].parse().ok()?;
                if !offset[1..3].bytes().all(|c| c.is_ascii_digit())
                    || !offset[4..6].bytes().all(|c| c.is_ascii_digit())
                    || hours > 23
                    || minutes > 59
                {
                    return None;
                }
                Some(sign * (hours * 60 + minutes))
            }
        };
        Some(t)
    }

    /// Its Ion text, to its precision.
    pub fn to_text(self) -> String {
        let mut out = format!("{:04}", self.year);
        if self.precision == Precision::Year {
            out.push('T');
            return out;
        }
        let _ = write!(out, "-{:02}", self.month);
        if self.precision == Precision::Month {
            out.push('T');
            return out;
        }
        let _ = write!(out, "-{:02}T", self.day);
        if self.precision == Precision::Day {
            return out;
        }
        let _ = write!(out, "{:02}:{:02}", self.hour, self.minute);
        if self.precision >= Precision::Second {
            let _ = write!(out, ":{:02}", self.second);
        }
        if let Precision::Fraction(n) = self.precision {
            let fraction = format!("{:09}", self.nanos);
            let _ = write!(out, ".{}", &fraction[..n as usize]);
        }
        out.push_str(&offset_text(self.offset));
        out
    }

    /// Seconds since 1970-01-01, local (as if its offset were UTC).
    fn local_seconds(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day) * DAY
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }

    /// The instant it is, in nanoseconds since 1970 (UTC).
    pub fn instant(&self) -> i128 {
        let offset = i64::from(self.offset.unwrap_or(0)) * 60;
        i128::from(self.local_seconds() - offset) * NANOS + i128::from(self.nanos)
    }

    /// The timestamp `local` seconds (and `nanos`) after 1970, local, with
    /// `self`'s offset and `precision`.
    fn at_local(
        &self,
        local: i64,
        nanos: u32,
        precision: Precision,
    ) -> Result<Timestamp, SelectError> {
        let (year, month, day) = civil_from_days(local.div_euclid(DAY));
        if !(1..=9999).contains(&year) {
            return Err(out_of_range());
        }
        let secs = local.rem_euclid(DAY);
        Ok(Timestamp {
            year: year as i32,
            month,
            day,
            hour: (secs / 3600) as u8,
            minute: (secs / 60 % 60) as u8,
            second: (secs % 60) as u8,
            nanos,
            offset: if precision >= Precision::Minute {
                self.offset
            } else {
                None
            },
            precision,
        })
    }

    /// `DATE_ADD(part, n, self)`: at least as precise as `part` is.
    pub fn add(&self, part: Part, n: i64) -> Result<Timestamp, SelectError> {
        let precision = self.precision.max(match part {
            Part::Year => Precision::Year,
            Part::Month => Precision::Month,
            Part::Day => Precision::Day,
            Part::Hour | Part::Minute => Precision::Minute,
            _ => Precision::Second,
        });
        let months = match part {
            Part::Year => n.checked_mul(12),
            Part::Month => Some(n),
            _ => None,
        };
        if let Some(months) = months {
            let total = (i64::from(self.year) * 12 + i64::from(self.month) - 1)
                .checked_add(months)
                .ok_or_else(out_of_range)?;
            let year = total.div_euclid(12);
            if !(1..=9999).contains(&year) {
                return Err(out_of_range());
            }
            let month = (total.rem_euclid(12) + 1) as u8;
            // The 31st of a month plus a month is the next month's last.
            let day = self.day.min(days_in_month(year as i32, month));
            return Ok(Timestamp {
                year: year as i32,
                month,
                day,
                precision,
                ..*self
            });
        }
        let seconds = match part {
            Part::Day => n.checked_mul(DAY),
            Part::Hour => n.checked_mul(3600),
            Part::Minute => n.checked_mul(60),
            _ => Some(n),
        };
        let local = seconds
            .and_then(|s| self.local_seconds().checked_add(s))
            .ok_or_else(out_of_range)?;
        self.at_local(local, self.nanos, precision)
    }

    /// `DATE_DIFF(part, self, later)`: how many whole `part`s `later` is
    /// after `self` (negative if before).
    pub fn diff(&self, part: Part, later: &Timestamp) -> i64 {
        match part {
            Part::Year | Part::Month => {
                // `later` at `self`'s offset, to compare their dates.
                let shift =
                    i64::from(self.offset.unwrap_or(0)) - i64::from(later.offset.unwrap_or(0));
                let local = later.local_seconds() + shift * 60;
                let Ok(later) = self.at_local(local, later.nanos, Precision::Fraction(9)) else {
                    return 0;
                };
                let mut months = (i64::from(later.year) - i64::from(self.year)) * 12
                    + i64::from(later.month)
                    - i64::from(self.month);
                // Only whole months: not if `later`'s day and time in its
                // month come before `self`'s in its.
                let within = |t: &Timestamp| (t.day, t.hour, t.minute, t.second, t.nanos);
                match within(&later).cmp(&within(self)) {
                    Ordering::Less if months > 0 => months -= 1,
                    Ordering::Greater if months < 0 => months += 1,
                    _ => {}
                }
                match part {
                    Part::Year => months / 12,
                    _ => months,
                }
            }
            _ => {
                let unit = match part {
                    Part::Day => i128::from(DAY) * NANOS,
                    Part::Hour => 3600 * NANOS,
                    Part::Minute => 60 * NANOS,
                    _ => NANOS,
                };
                ((later.instant() - self.instant()) / unit) as i64
            }
        }
    }

    /// `EXTRACT(part FROM self)`.
    pub fn extract(&self, part: Part) -> i64 {
        let offset = i64::from(self.offset.unwrap_or(0));
        match part {
            Part::Year => i64::from(self.year),
            Part::Month => i64::from(self.month),
            Part::Day => i64::from(self.day),
            Part::Hour => i64::from(self.hour),
            Part::Minute => i64::from(self.minute),
            Part::Second => i64::from(self.second),
            Part::TimezoneHour => offset / 60,
            Part::TimezoneMinute => offset % 60,
        }
    }

    /// Now, to the millisecond, in UTC.
    pub fn now() -> Timestamp {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let utc = Timestamp {
            year: 1970,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
            nanos: 0,
            offset: Some(0),
            precision: Precision::Fraction(3),
        };
        let millis = since.subsec_millis() * 1_000_000;
        utc.at_local(since.as_secs() as i64, millis, Precision::Fraction(3))
            .unwrap_or(utc)
    }
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

fn pattern_error(code: &'static str, message: String) -> SelectError {
    SelectError::new(code, message)
}

impl Timestamp {
    /// `TO_STRING(self, pattern)`: `pattern`'s letters, as AWS's table has
    /// them (Java's `DateTimeFormatter`'s): `y`, `M`, `d`, `a`, `h`, `H`,
    /// `m`, `s`, `S`, `n`, `X`, `x`. Other characters are themselves, and
    /// so is text in single quotes (`''` is a quote).
    pub fn format(&self, pattern: &str) -> Result<String, SelectError> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\'' {
                // `''` is a quote; else quoted text, to the next quote.
                if chars.get(i + 1) == Some(&'\'') {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                let mut j = i + 1;
                loop {
                    match chars.get(j) {
                        None => {
                            return Err(pattern_error(
                                "EvaluatorUnterminatedTimestampFormatPatternToken",
                                format!(
                                    "The time format pattern '{pattern}' has an unclosed quote."
                                ),
                            ));
                        }
                        Some('\'') if chars.get(j + 1) == Some(&'\'') => {
                            out.push('\'');
                            j += 2;
                        }
                        Some('\'') => break,
                        Some(c) => {
                            out.push(*c);
                            j += 1;
                        }
                    }
                }
                i = j + 1;
                continue;
            }
            if !c.is_ascii_alphabetic() {
                out.push(c);
                i += 1;
                continue;
            }
            let n = chars[i..].iter().take_while(|&&x| x == c).count();
            i += n;
            self.field(c, n, &mut out).map_err(|()| {
                let token: String = std::iter::repeat_n(c, n).collect();
                match "yMdahHmsSnXx".contains(c) {
                    true => pattern_error(
                        "EvaluatorInvalidTimestampFormatPatternToken",
                        format!("'{token}' isn't a time format pattern."),
                    ),
                    false => pattern_error(
                        "EvaluatorInvalidTimestampFormatPatternSymbol",
                        format!("'{c}' isn't a symbol of time format patterns."),
                    ),
                }
            })?;
        }
        Ok(out)
    }

    /// Writes the pattern letter `c`, `n` times, to `out`.
    fn field(&self, c: char, n: usize, out: &mut String) -> Result<(), ()> {
        let padded = |out: &mut String, value: u32, width: usize| {
            let _ = write!(out, "{value:0width$}");
        };
        match (c, n) {
            ('y', 2) => padded(out, (self.year % 100) as u32, 2),
            ('y', _) => padded(out, self.year as u32, n),
            ('M', 1 | 2) => padded(out, u32::from(self.month), n),
            ('M', 3) => out.push_str(&MONTHS[self.month as usize - 1][..3]),
            ('M', 4) => out.push_str(MONTHS[self.month as usize - 1]),
            ('M', 5) => out.push_str(&MONTHS[self.month as usize - 1][..1]),
            ('d', 1 | 2) => padded(out, u32::from(self.day), n),
            ('a', 1) => out.push_str(if self.hour < 12 { "AM" } else { "PM" }),
            ('h', 1 | 2) => {
                let hour = match self.hour % 12 {
                    0 => 12,
                    h => h,
                };
                padded(out, u32::from(hour), n)
            }
            ('H', 1 | 2) => padded(out, u32::from(self.hour), n),
            ('m', 1 | 2) => padded(out, u32::from(self.minute), n),
            ('s', 1 | 2) => padded(out, u32::from(self.second), n),
            // The fraction, truncated to `n` digits.
            ('S', 1..=9) => {
                let fraction = format!("{:09}", self.nanos);
                out.push_str(&fraction[..n]);
            }
            ('n', 1..=9) => padded(out, self.nanos, n),
            ('X' | 'x', 1..=5) => {
                let offset = i32::from(self.offset.unwrap_or(0));
                if c == 'X' && offset == 0 {
                    out.push('Z');
                    return Ok(());
                }
                let sign = if offset < 0 { '-' } else { '+' };
                let (hours, minutes) = (offset.abs() / 60, offset.abs() % 60);
                let _ = match n {
                    // The hours, and the minutes if there are any.
                    1 if minutes == 0 => write!(out, "{sign}{hours:02}"),
                    1 | 2 | 4 => write!(out, "{sign}{hours:02}{minutes:02}"),
                    _ => write!(out, "{sign}{hours:02}:{minutes:02}"),
                };
            }
            _ => return Err(()),
        }
        Ok(())
    }
}

/// An offset's text: `Z`, `-00:00` (unknown), or `+hh:mm`.
fn offset_text(offset: Option<i16>) -> String {
    match offset {
        None => "-00:00".to_owned(),
        Some(0) => "Z".to_owned(),
        Some(m) => {
            let sign = if m < 0 { '-' } else { '+' };
            format!("{sign}{:02}:{:02}", m.abs() / 60, m.abs() % 60)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(text: &str) -> Timestamp {
        Timestamp::parse(text).unwrap()
    }

    #[test]
    fn reads_and_writes_ion_text() {
        for text in [
            "2007T",
            "2007-02T",
            "2007-02-23T",
            "2007-02-23T12:14Z",
            "2007-02-23T12:14:33Z",
            "2007-02-23T12:14:33.079-08:00",
            "2007-02-23T12:14:33.000000001+05:30",
            "2007-02-23T12:14-00:00",
        ] {
            assert_eq!(ts(text).to_text(), text);
        }
        assert_eq!(ts("2007-02-23").to_text(), "2007-02-23T");
        assert_eq!(ts("2010-01-01T23:00").to_text(), "2010-01-01T23:00-00:00");
        for bad in [
            "2007",
            "07T",
            "2007-13T",
            "2007-02-30",
            "2007-02-23T25:00Z",
            "2007-02-23T12:14:33.Z",
            "2007-02-23T12:14+5",
            "x",
            "",
            "0000T",
            "2007-02-23T12:14:33.0123456789Z",
        ] {
            assert!(Timestamp::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn compares_instants() {
        assert_eq!(
            ts("2007-02-23T12:00Z").instant(),
            ts("2007-02-23T04:00-08:00").instant()
        );
        assert_eq!(ts("1970T").instant(), 0);
        assert_eq!(ts("1969-12-31T23:59:59Z").instant(), -NANOS);
    }

    /// AWS's examples of DATE_ADD.
    #[test]
    fn adds() {
        let add = |part, n, t: &str| ts(t).add(part, n).unwrap().to_text();
        assert_eq!(add(Part::Year, 5, "2010-01-01T"), "2015-01-01T");
        assert_eq!(add(Part::Month, 1, "2010T"), "2010-02T");
        assert_eq!(add(Part::Month, 13, "2010T"), "2011-02T");
        assert_eq!(add(Part::Day, -1, "2017-01-10T"), "2017-01-09T");
        assert_eq!(add(Part::Hour, 1, "2017T"), "2017-01-01T01:00-00:00");
        assert_eq!(add(Part::Hour, 1, "2017-01-02T03:04Z"), "2017-01-02T04:04Z");
        assert_eq!(
            add(Part::Minute, 1, "2017-01-02T03:04:05.006Z"),
            "2017-01-02T03:05:05.006Z"
        );
        assert_eq!(
            add(Part::Second, 1, "2017-01-02T03:04:05.006Z"),
            "2017-01-02T03:04:06.006Z"
        );
        // And what they don't show: the end of a month, and leap years.
        assert_eq!(add(Part::Month, 1, "2011-01-31T"), "2011-02-28T");
        assert_eq!(add(Part::Year, 1, "2012-02-29T"), "2013-02-28T");
        assert_eq!(add(Part::Day, 1, "2012-02-28T"), "2012-02-29T");
        assert_eq!(
            add(Part::Second, -1, "2000-01-01T00:00:00Z"),
            "1999-12-31T23:59:59Z"
        );
        assert!(ts("9999T").add(Part::Year, 1).is_err());
        assert!(ts("2000T").add(Part::Day, i64::MAX).is_err());
    }

    /// AWS's examples of DATE_DIFF.
    #[test]
    fn diffs() {
        let diff = |part, a: &str, b: &str| ts(a).diff(part, &ts(b));
        assert_eq!(diff(Part::Year, "2010-01-01T", "2011-01-01T"), 1);
        assert_eq!(diff(Part::Year, "2010-12T", "2011-01T"), 0);
        assert_eq!(diff(Part::Month, "2010T", "2010-05T"), 4);
        assert_eq!(diff(Part::Month, "2010T", "2011T"), 12);
        assert_eq!(diff(Part::Month, "2011T", "2010T"), -12);
        assert_eq!(diff(Part::Day, "2010-01-01T23:00", "2010-01-02T01:00"), 0);
        // Whole months only, across offsets.
        assert_eq!(diff(Part::Month, "2010-01-31T", "2010-02-28T"), 0);
        assert_eq!(diff(Part::Month, "2010-01-15T", "2010-02-15T"), 1);
        assert_eq!(diff(Part::Month, "2010-02-15T", "2010-01-16T"), 0);
        assert_eq!(
            diff(Part::Hour, "2010-01-01T00:00Z", "2010-01-01T00:00-02:00"),
            2
        );
        assert_eq!(diff(Part::Second, "2010T", "2010-01-01T00:00:01.9Z"), 1);
    }

    /// AWS's examples of EXTRACT.
    #[test]
    fn extracts() {
        let t = ts("2017-01-02T03:04:05+07:08");
        assert_eq!(ts("2010-01-01T").extract(Part::Year), 2010);
        assert_eq!(ts("2010T").extract(Part::Month), 1);
        assert_eq!(ts("2010-10T").extract(Part::Month), 10);
        assert_eq!(t.extract(Part::Hour), 3);
        assert_eq!(t.extract(Part::Minute), 4);
        assert_eq!(t.extract(Part::TimezoneHour), 7);
        assert_eq!(t.extract(Part::TimezoneMinute), 8);
        let west = ts("2017-01-02T03:04:05-07:30");
        assert_eq!(west.extract(Part::TimezoneHour), -7);
        assert_eq!(west.extract(Part::TimezoneMinute), -30);
    }

    /// AWS's examples of TO_STRING (but the one with `+08:00Z`, which
    /// isn't a timestamp), and its table's patterns.
    #[test]
    fn formats() {
        let moon = ts("1969-07-20T20:18Z");
        let east = ts("1969-07-20T20:18+08:00");
        let format = |t: &Timestamp, p: &str| t.format(p).unwrap();
        assert_eq!(format(&moon, "MMMM d, y"), "July 20, 1969");
        assert_eq!(format(&moon, "MMM d, yyyy"), "Jul 20, 1969");
        assert_eq!(format(&moon, "M-d-yy"), "7-20-69");
        assert_eq!(format(&moon, "MM-d-y"), "07-20-1969");
        assert_eq!(format(&moon, "MMMM d, y h:m a"), "July 20, 1969 8:18 PM");
        assert_eq!(format(&moon, "y-MM-dd'T'H:m:ssX"), "1969-07-20T20:18:00Z");
        assert_eq!(
            format(&east, "y-MM-dd'T'H:m:ssXXXX"),
            "1969-07-20T20:18:00+0800"
        );
        assert_eq!(
            format(&east, "y-MM-dd'T'H:m:ssXXXXX"),
            "1969-07-20T20:18:00+08:00"
        );
        let t = ts("2001-01-02T03:04:05.06+07:30");
        assert_eq!(format(&t, "MMMMM dd hh HH mm ss"), "J 02 03 03 04 05");
        assert_eq!(
            format(&t, "S SS SSS SSSSSSSSS n"),
            "0 06 060 060000000 60000000"
        );
        assert_eq!(
            format(&t, "X|XX|XXX|x|xx|xxx"),
            "+0730|+0730|+07:30|+0730|+0730|+07:30"
        );
        assert_eq!(format(&ts("2001T"), "X x xxx h a"), "Z +00 +00:00 12 AM");
        assert_eq!(format(&moon, "'it''s' '' y"), "it's ' 1969");
        let code = |p: &str| moon.format(p).unwrap_err().code;
        assert_eq!(
            code("y 'open"),
            "EvaluatorUnterminatedTimestampFormatPatternToken"
        );
        assert_eq!(code("Q"), "EvaluatorInvalidTimestampFormatPatternSymbol");
        assert_eq!(
            code("MMMMMM"),
            "EvaluatorInvalidTimestampFormatPatternToken"
        );
    }

    #[test]
    fn the_calendar_is_right() {
        for days in -800_000..800_000 {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y as i32, m, d), days);
        }
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(Timestamp::now().precision, Precision::Fraction(3));
    }
}
