use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, header};

/// Outcome of evaluating RFC 7232 conditional-request headers.
#[derive(Debug, PartialEq, Eq)]
pub enum Precondition {
    /// All conditions passed; process the request normally.
    Proceed,
    /// A read whose representation is unchanged: respond 304 Not Modified.
    NotModified,
    /// A guard failed: respond 412 Precondition Failed.
    Failed,
}

/// The conditional-request headers (RFC 7232), or their `x-amz-copy-source-*`
/// equivalents for the copy endpoints. An absent header is `None`.
#[derive(Default)]
pub struct Preconditions {
    if_match: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
    if_unmodified_since: Option<String>,
}

impl Preconditions {
    /// Reads the standard conditional headers (If-Match, If-None-Match,
    /// If-Modified-Since, If-Unmodified-Since) — used by GET and HEAD.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Preconditions {
            if_match: header(headers, "if-match"),
            if_none_match: header(headers, "if-none-match"),
            if_modified_since: header(headers, "if-modified-since"),
            if_unmodified_since: header(headers, "if-unmodified-since"),
        }
    }

    /// Reads the copy-source conditional headers (`x-amz-copy-source-if-*`), which
    /// gate a copy on the *source* object's state.
    pub fn from_copy_source_headers(headers: &HeaderMap) -> Self {
        Preconditions {
            if_match: header(headers, "x-amz-copy-source-if-match"),
            if_none_match: header(headers, "x-amz-copy-source-if-none-match"),
            if_modified_since: header(headers, "x-amz-copy-source-if-modified-since"),
            if_unmodified_since: header(headers, "x-amz-copy-source-if-unmodified-since"),
        }
    }

    /// Evaluates the conditions against a resource's current `etag` (stored form,
    /// e.g. `9a…` or `9a…-3`) and `last_modified` (Unix seconds). `is_read` selects
    /// GET/HEAD semantics, where a failed If-None-Match / If-Modified-Since yields
    /// 304 rather than 412. Follows the RFC 7232 §6 precedence.
    pub fn evaluate(&self, etag: &str, last_modified: i64, is_read: bool) -> Precondition {
        // Step 1/2: If-Match, else (only if absent) If-Unmodified-Since.
        if let Some(if_match) = &self.if_match {
            if !etag_matches(if_match, etag) {
                return Precondition::Failed;
            }
        } else if let Some(since) = &self.if_unmodified_since {
            // A malformed HTTP-date is ignored (RFC 7232).
            if let Some(since) = parse_http_date(since)
                && last_modified > since
            {
                return Precondition::Failed;
            }
        }
        // Step 3/4: If-None-Match, else (only if absent) If-Modified-Since — the
        // latter for reads only.
        if let Some(if_none_match) = &self.if_none_match {
            if etag_matches(if_none_match, etag) {
                return if is_read {
                    Precondition::NotModified
                } else {
                    Precondition::Failed
                };
            }
        } else if is_read
            && let Some(since) = &self.if_modified_since
            && let Some(since) = parse_http_date(since)
            && last_modified <= since
        {
            return Precondition::NotModified;
        }
        Precondition::Proceed
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Whether `header` (an If-[None-]Match value: `*`, or a comma-separated list of
/// possibly weak, quoted entity-tags) matches the resource's `etag`.
fn etag_matches(header: &str, etag: &str) -> bool {
    let header = header.trim();
    if header == "*" {
        return true;
    }
    header.split(',').any(|candidate| {
        // Strip an optional weak indicator and the surrounding quotes; our stored
        // etags are unquoted, so a quoted `"9a…"` (or `"9a…-3"`) compares equal.
        let c = candidate.trim();
        let c = c.strip_prefix("W/").unwrap_or(c);
        c.trim_matches('"') == etag
    })
}

/// Parses an RFC 1123 HTTP-date (`Sun, 06 Nov 1994 08:49:37 GMT`) into Unix
/// seconds. Returns None for any other/malformed input, so the caller can ignore
/// an unparseable date as RFC 7232 requires. The zone is assumed GMT (as HTTP
/// mandates); any trailing token is ignored.
fn parse_http_date(s: &str) -> Option<i64> {
    // Drop the leading "Wkd, " day-of-week.
    let rest = s.trim().split_once(", ")?.1;
    let mut fields = rest.split(' ');
    let day: i64 = fields.next()?.parse().ok()?;
    let month = month_number(fields.next()?)?;
    let year: i64 = fields.next()?.parse().ok()?;
    let mut hms = fields.next()?.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let min: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next()?.parse().ok()?;
    if !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn month_number(m: &str) -> Option<i64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days since 1970-01-01 for a proleptic-Gregorian y/m/d (Howard Hinnant's
/// algorithm). `m` is 1..=12.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A 304 Not Modified response carrying the validators a 200 would (ETag,
/// Last-Modified) and no body.
pub fn not_modified(etag: &str, last_modified: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::ETAG, format!("\"{etag}\""))
        .header(header::LAST_MODIFIED, last_modified)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed reference instant: "Sun, 06 Nov 1994 08:49:37 GMT" == 784111777.
    const REF: i64 = 784_111_777;
    const REF_DATE: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
    const EARLIER: &str = "Sat, 05 Nov 1994 08:49:37 GMT";
    const LATER: &str = "Mon, 07 Nov 1994 08:49:37 GMT";

    #[test]
    fn parses_rfc1123_dates() {
        assert_eq!(parse_http_date(REF_DATE), Some(REF));
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
    }

    #[test]
    fn rejects_malformed_dates() {
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date(""), None);
        assert_eq!(parse_http_date("Sun, 06 Foo 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 06 Nov 1994 25:49:37 GMT"), None);
    }

    #[test]
    fn etag_matching() {
        assert!(etag_matches("*", "abc"));
        assert!(etag_matches("\"abc\"", "abc"));
        assert!(etag_matches("W/\"abc\"", "abc"));
        assert!(etag_matches("\"x\", \"abc\", \"y\"", "abc"));
        assert!(etag_matches("\"abc-3\"", "abc-3"));
        assert!(!etag_matches("\"abc\"", "def"));
    }

    fn conds(
        if_match: Option<&str>,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
        if_unmodified_since: Option<&str>,
    ) -> Preconditions {
        Preconditions {
            if_match: if_match.map(str::to_owned),
            if_none_match: if_none_match.map(str::to_owned),
            if_modified_since: if_modified_since.map(str::to_owned),
            if_unmodified_since: if_unmodified_since.map(str::to_owned),
        }
    }

    #[test]
    fn no_conditions_proceed() {
        assert_eq!(conds(None, None, None, None).evaluate("abc", REF, true), Precondition::Proceed);
    }

    #[test]
    fn if_match() {
        assert_eq!(conds(Some("\"abc\""), None, None, None).evaluate("abc", REF, true), Precondition::Proceed);
        assert_eq!(conds(Some("\"def\""), None, None, None).evaluate("abc", REF, true), Precondition::Failed);
    }

    #[test]
    fn if_none_match_read_vs_write() {
        // A match means "not modified" for a read, but a failed guard for a write.
        assert_eq!(conds(None, Some("\"abc\""), None, None).evaluate("abc", REF, true), Precondition::NotModified);
        assert_eq!(conds(None, Some("\"abc\""), None, None).evaluate("abc", REF, false), Precondition::Failed);
        // No match: proceed either way.
        assert_eq!(conds(None, Some("\"def\""), None, None).evaluate("abc", REF, true), Precondition::Proceed);
    }

    #[test]
    fn if_unmodified_since() {
        // Modified after the date → failed; at/before → proceed.
        assert_eq!(conds(None, None, None, Some(EARLIER)).evaluate("abc", REF, true), Precondition::Failed);
        assert_eq!(conds(None, None, None, Some(REF_DATE)).evaluate("abc", REF, true), Precondition::Proceed);
        assert_eq!(conds(None, None, None, Some(LATER)).evaluate("abc", REF, true), Precondition::Proceed);
        // A malformed date is ignored.
        assert_eq!(conds(None, None, None, Some("garbage")).evaluate("abc", REF, true), Precondition::Proceed);
    }

    #[test]
    fn if_modified_since_read_only() {
        // Not modified since the date → 304 (read); modified → proceed.
        assert_eq!(conds(None, None, Some(REF_DATE), None).evaluate("abc", REF, true), Precondition::NotModified);
        assert_eq!(conds(None, None, Some(EARLIER), None).evaluate("abc", REF, true), Precondition::Proceed);
        // Ignored for writes (precedence step 4 is read-only).
        assert_eq!(conds(None, None, Some(REF_DATE), None).evaluate("abc", REF, false), Precondition::Proceed);
    }

    #[test]
    fn if_match_takes_precedence_over_unmodified_since() {
        // If-Match present and true → If-Unmodified-Since is not consulted.
        assert_eq!(
            conds(Some("\"abc\""), None, None, Some(EARLIER)).evaluate("abc", REF, true),
            Precondition::Proceed
        );
    }
}
