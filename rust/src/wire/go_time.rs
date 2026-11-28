//! A time read as Go's `time.Time` reads one from JSON (`Time.UnmarshalJSON`).
//!
//! What Go does, measured with go1.27.1:
//!
//! - only a JSON string is a time; a number, `true` or an object is an error. `null`
//!   leaves the time as it was (a time never set is Go's zero time);
//! - the string is unescaped first, so `"…\u005a"` reads as `…Z`;
//! - its bytes are then read as `time.Parse(time.RFC3339, …)` reads them: four digits of year,
//!   two of month and day, `T`, an hour of one or two digits, two of minute and second,
//!   an optional fraction after `.` or `,` (any number of digits, nine count), then `Z`
//!   or `±hh:mm`. Hour 0 to 23, minute and second 0 to 59 (no leap second), the day must
//!   be in the month. The offset may go up to `24:60`. `t`, `z` and spaces are not taken.
//!
//! The time is in Unix seconds, rounded down, and the nanoseconds past them.
//!
//! Go writes a time back as `Time.MarshalJSON` does ([`to_go_text`]), not as it came.

/// A Go time: Unix seconds (rounded down) and the nanoseconds past them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoTime {
    pub unix: i64,
    pub nanos: u32,
}

fn two_digits(b: &[u8]) -> Option<i64> {
    match b {
        [a, c, ..] if a.is_ascii_digit() && c.is_ascii_digit() => {
            Some(i64::from(a - b'0') * 10 + i64::from(c - b'0'))
        }
        _ => None,
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn literal(v: &mut &[u8], c: u8) -> Option<()> {
    let (&first, rest) = v.split_first()?;
    (first == c).then(|| *v = rest)
}

fn fixed2(v: &mut &[u8]) -> Option<i64> {
    let n = two_digits(v)?;
    *v = &v[2..];
    Some(n)
}

/// The bytes of a time as `time.Parse(time.RFC3339, …)` takes them, or `None` where Go
/// gives an error.
pub fn parse(s: &[u8]) -> Option<GoTime> {
    parse_with_offset(s).map(|(t, _)| t)
}

/// As [`parse`], with the offset from UTC in seconds as written (`+24:60` is 90 000).
fn parse_with_offset(s: &[u8]) -> Option<(GoTime, i64)> {
    let mut v = s;
    if v.len() < 4 || !v[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year = v[..4]
        .iter()
        .fold(0_i64, |n, d| n * 10 + i64::from(d - b'0'));
    v = &v[4..];
    literal(&mut v, b'-')?;
    let month = fixed2(&mut v).filter(|m| (1..=12).contains(m))?;
    literal(&mut v, b'-')?;
    let day = fixed2(&mut v)?;
    literal(&mut v, b'T')?;
    // The hour alone may have one digit.
    let hour = match v {
        [a, ..] if !a.is_ascii_digit() => return None,
        [a, c, ..] if c.is_ascii_digit() => {
            v = &v[2..];
            i64::from(a - b'0') * 10 + i64::from(c - b'0')
        }
        [a, ..] => {
            v = &v[1..];
            i64::from(a - b'0')
        }
        [] => return None,
    };
    if hour > 23 {
        return None;
    }
    literal(&mut v, b':')?;
    let min = fixed2(&mut v).filter(|m| *m < 60)?;
    literal(&mut v, b':')?;
    let sec = fixed2(&mut v).filter(|s| *s < 60)?;

    let mut nanos = 0_u32;
    if v.len() >= 2 && (v[0] == b'.' || v[0] == b',') && v[1].is_ascii_digit() {
        let digits = v[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        // Nine digits count, the rest are read and dropped.
        let mut kept = v[1..=digits].iter().take(9);
        for _ in 0..9 {
            nanos = nanos * 10 + kept.next().map_or(0, |d| u32::from(d - b'0'));
        }
        v = &v[1 + digits..];
    }

    let offset = if v.first() == Some(&b'Z') {
        v = &v[1..];
        0
    } else {
        if v.len() < 6 || v[3] != b':' {
            return None;
        }
        let hr = two_digits(&v[1..3])?;
        let mm = two_digits(&v[4..6])?;
        if hr > 24 || mm > 60 {
            return None;
        }
        let sign = match v[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        v = &v[6..];
        sign * (hr * 3600 + mm * 60)
    };
    if !v.is_empty() || day < 1 || day > days_in(month, year) {
        return None;
    }
    let unix = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec - offset;
    Some((GoTime { unix, nanos }, offset))
}

/// The date of a day counted from 1970-01-01.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// A time's text (as [`parse`] takes it) as Go's `Time.MarshalJSON` writes the time it reads
/// (go1.27.1, RFC 3339 with nanoseconds): the date and clock in the time's own offset, two
/// digits for the hour, the fraction without the zeros at its end (none when it is zero), and
/// `Z` for an offset of 0, `+00:00` and `-00:00` too. Go writes the offset from its minutes,
/// so `+01:60` is `+02:00`, and refuses to write an offset of 24 hours or more, as here.
pub fn to_go_text(s: &str) -> Result<String, String> {
    let (t, offset) =
        parse_with_offset(s.as_bytes()).ok_or_else(|| format!("neispravno vrijeme {s}"))?;
    let wall = t.unix + offset;
    let (year, month, day) = civil_from_days(wall.div_euclid(86_400));
    let secs = wall.rem_euclid(86_400);
    if !(0..=9999).contains(&year) {
        return Err(format!("Go ne zapisuje godinu {year}"));
    }
    let mut out = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    );
    if t.nanos > 0 {
        let fraction = format!("{:09}", t.nanos);
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    let zone = offset / 60;
    if zone == 0 {
        out.push('Z');
        return Ok(out);
    }
    if zone.abs() / 60 >= 24 {
        return Err(format!("Go ne zapisuje pomak {s}"));
    }
    let sign = if zone < 0 { '-' } else { '+' };
    out.push_str(&format!(
        "{sign}{:02}:{:02}",
        zone.abs() / 60,
        zone.abs() % 60
    ));
    Ok(out)
}

/// A JSON value (its raw text) read as `Time.UnmarshalJSON` reads it. `null` is
/// `Ok(None)`: Go leaves the time as it was.
pub fn from_json(raw: &str) -> Result<Option<GoTime>, String> {
    if raw == "null" {
        return Ok(None);
    }
    if !raw.starts_with('"') {
        return Err("vrijeme nije JSON tekst".into());
    }
    // A lone surrogate does not unescape here; Go puts U+FFFD for it, which is no time
    // either.
    let text: String = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    parse(text.as_bytes())
        .map(Some)
        .ok_or_else(|| format!("neispravno vrijeme {raw}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(raw: &str) -> String {
        match from_json(raw) {
            Ok(None) => "null".into(),
            Ok(Some(t)) => format!("{}.{:09}", t.unix, t.nanos),
            Err(_) => "GRESKA".into(),
        }
    }

    /// (JSON value, what Go's `Time.UnmarshalJSON` gives: Unix seconds rounded down and
    /// nanoseconds, or `GRESKA`). Go column measured with go1.27.1.
    const EDGES: &[(&str, &str)] = &[
        (r#""2025-10-09T08:53:20Z""#, "1760000000.000000000"),
        (r#""2025-10-09T10:53:20+02:00""#, "1760000000.000000000"),
        (r#""2025-10-09T08:53:20.5Z""#, "1760000000.500000000"),
        (r#""2025-10-09T08:53:20,5Z""#, "1760000000.500000000"),
        (
            r#""2025-10-09T08:53:20.1234567899Z""#,
            "1760000000.123456789",
        ),
        (r#""2025-10-09T8:53:20Z""#, "1760000000.000000000"),
        (r#""2025-10-09T08:53:20+24:60""#, "1759910000.000000000"),
        (r#""0001-01-01T00:00:00Z""#, "-62135596800.000000000"),
        (r#""0001-01-01T00:00:00.5Z""#, "-62135596800.500000000"),
        (r#""0000-02-29T00:00:00Z""#, "-62162121600.000000000"),
        (r#""1969-12-31T23:59:59.5Z""#, "-1.500000000"),
        ("null", "null"),
        (r#""2025-10-09t08:53:20Z""#, "GRESKA"),
        (r#""2025-10-09T08:53:20z""#, "GRESKA"),
        (r#""2025-10-09T08:53:60Z""#, "GRESKA"),
        (r#""2025-10-09T24:00:00Z""#, "GRESKA"),
        (r#""2025-02-29T00:00:00Z""#, "GRESKA"),
        (r#""2025-10-09T08:53:20+25:00""#, "GRESKA"),
        (r#""2025-10-09T08:53:20+0200""#, "GRESKA"),
        (r#""2025-10-09T08:53:20.Z""#, "GRESKA"),
        (r#""2025-10-09T08:53:20\u005a""#, "1760000000.000000000"),
        (r#""\u0032025-10-09T08:53:20Z""#, "1760000000.000000000"),
        (r#""2025-10-09T08:53:20\ud800""#, "GRESKA"),
        (r#""2025-10-09 08:53:20Z""#, "GRESKA"),
        (r#""2025-10-09T08:53:20Z ""#, "GRESKA"),
        (r#"" 2025-10-09T08:53:20Z""#, "GRESKA"),
        (r#""2025-1-09T08:53:20Z""#, "GRESKA"),
        (r#""+025-10-09T08:53:20Z""#, "GRESKA"),
        (r#""10000-10-09T08:53:20Z""#, "GRESKA"),
        ("1760000000", "GRESKA"),
        ("0", "GRESKA"),
        ("true", "GRESKA"),
        ("{}", "GRESKA"),
        (r#""""#, "GRESKA"),
    ];

    #[test]
    fn times_read_as_in_go() {
        for (raw, go) in EDGES {
            assert_eq!(read(raw), *go, "{raw}");
        }
    }

    /// (a time as it came, what Go's `json.Marshal` writes for the time it reads, or
    /// `MARSHALERR`). Go column measured with go1.27.1 on a version of the ledger.
    const WRITES: &[(&str, &str)] = &[
        ("2025-10-09T08:53:20Z", "2025-10-09T08:53:20Z"),
        ("2025-10-09T08:53:20+00:00", "2025-10-09T08:53:20Z"),
        ("2025-10-09T08:53:20-00:00", "2025-10-09T08:53:20Z"),
        ("2025-10-09T08:53:20.500Z", "2025-10-09T08:53:20.5Z"),
        ("2025-10-09T08:53:20.000Z", "2025-10-09T08:53:20Z"),
        ("2025-10-09T08:53:20,25Z", "2025-10-09T08:53:20.25Z"),
        (
            "2025-10-09T08:53:20.1234567899Z",
            "2025-10-09T08:53:20.123456789Z",
        ),
        ("2025-10-09T8:53:20Z", "2025-10-09T08:53:20Z"),
        ("2025-10-09T10:53:20+02:00", "2025-10-09T10:53:20+02:00"),
        ("2025-10-09T10:53:20-02:30", "2025-10-09T10:53:20-02:30"),
        ("2025-10-09T10:53:20+01:60", "2025-10-09T10:53:20+02:00"),
        ("2025-10-09T10:53:20+00:60", "2025-10-09T10:53:20+01:00"),
        ("2026-01-01T00:00:00+23:59", "2026-01-01T00:00:00+23:59"),
        ("2026-01-01T00:00:00+23:60", "MARSHALERR"),
        ("2026-01-01T00:00:00+24:00", "MARSHALERR"),
        ("2026-01-01T00:00:00-24:00", "MARSHALERR"),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"),
        ("0001-01-01T00:00:00+01:00", "0001-01-01T00:00:00+01:00"),
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
        ("9999-12-31T23:59:59-01:00", "9999-12-31T23:59:59-01:00"),
        ("1969-12-31T23:59:59.5Z", "1969-12-31T23:59:59.5Z"),
    ];

    #[test]
    fn times_written_as_in_go() {
        for (text, go) in WRITES {
            let got = to_go_text(text).unwrap_or_else(|_| "MARSHALERR".into());
            assert_eq!(got, *go, "{text}");
        }
    }
}
