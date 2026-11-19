//! A batch job's manifest: the objects its tasks are on, one per line of a
//! CSV object (`S3BatchOperations_CSV_20180820`), each line the columns
//! its `Fields` name: `Bucket`, `Key`, and optionally `VersionId`, with
//! `Ignore` for columns that aren't any of those.
//!
//! Keys are URL-encoded, as S3's inventory reports write them (and Cairn's:
//! see `inventory`): `+` for a space, `%XX` for everything else that's
//! escaped. Columns may be quoted (`"…"`, with `""` for a quote), as
//! inventory reports' are. Lines end with `\n` (or `\r\n`); the last may
//! end without one.

use percent_encoding::percent_decode_str;

/// The format of a manifest of CSV lines.
pub const CSV: &str = "S3BatchOperations_CSV_20180820";
/// The format of an inventory report's `manifest.json`: its data files are
/// CSV or Parquet, as it says (see `source`), whatever the name says.
pub const INVENTORY: &str = "S3InventoryReport_CSV_20161130";
/// The format of a manifest a job generates (see `generate`): an inventory
/// report's `manifest.json` too, read as one is.
pub const GENERATED_INVENTORY: &str = "S3InventoryReport_CSV_20211130";
/// What a job with a manifest generator has as its manifest's format until
/// its manifest is generated (never CreateJob's).
pub const TO_BE_GENERATED: &str = "Generated";

/// Whether a manifest of `format` is an inventory report's `manifest.json`.
pub fn is_inventory(format: &str) -> bool {
    format == INVENTORY || format == GENERATED_INVENTORY
}

/// The longest key, in bytes, as S3 takes them.
const MAX_KEY: usize = 1024;

/// What a column of a manifest's lines is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Ignore,
    Bucket,
    Key,
    VersionId,
}

impl Field {
    pub fn parse(name: &str) -> Option<Field> {
        Some(match name {
            "Ignore" => Field::Ignore,
            "Bucket" => Field::Bucket,
            "Key" => Field::Key,
            "VersionId" => Field::VersionId,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Field::Ignore => "Ignore",
            Field::Bucket => "Bucket",
            Field::Key => "Key",
            Field::VersionId => "VersionId",
        }
    }
}

/// Why `fields` can't be a manifest's: each line needs a bucket and a key,
/// and may have a version ID, each in one column only.
pub fn check_fields(fields: &[Field]) -> Result<(), String> {
    let count = |field| fields.iter().filter(|f| **f == field).count();
    if count(Field::Bucket) != 1 || count(Field::Key) != 1 {
        return Err("A manifest's fields must include Bucket and Key, once each.".to_owned());
    }
    if count(Field::VersionId) > 1 {
        return Err("A manifest's fields may include VersionId once.".to_owned());
    }
    Ok(())
}

/// The object a task is on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub bucket: String,
    pub key: String,
    /// `None`: the current version.
    pub version_id: Option<String>,
}

/// The task of a line (without its line ending), whose columns are
/// `fields`, or why it isn't one.
pub fn parse_line(line: &str, fields: &[Field]) -> Result<Task, String> {
    let columns = columns(line)?;
    if columns.len() != fields.len() {
        return Err(format!("it has {} columns, not the {} its fields name", columns.len(), fields.len()));
    }
    let (mut bucket, mut key, mut version_id) = (None, None, None);
    for (field, column) in fields.iter().zip(columns) {
        match field {
            Field::Ignore => {}
            Field::Bucket => bucket = Some(column),
            Field::Key => key = Some(decode_key(&column)?),
            Field::VersionId => version_id = Some(column),
        }
    }
    task(bucket.unwrap_or_default(), key.unwrap_or_default(), version_id)
}

/// The task on version `version_id` (`None` or empty: the current one) of
/// `key` in `bucket`, or why it isn't one.
pub fn task(bucket: String, key: String, version_id: Option<String>) -> Result<Task, String> {
    if bucket.is_empty() {
        return Err("its bucket is empty".to_owned());
    }
    if key.is_empty() {
        return Err("its key is empty".to_owned());
    }
    if key.len() > MAX_KEY {
        return Err("its key is longer than 1024 bytes".to_owned());
    }
    Ok(Task { bucket, key, version_id: version_id.filter(|v| !v.is_empty()) })
}

/// A line's columns, unquoted.
fn columns(line: &str) -> Result<Vec<String>, String> {
    let mut columns = Vec::new();
    let mut chars = line.chars().peekable();
    loop {
        let mut column = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            loop {
                match chars.next() {
                    Some('"') if chars.peek() == Some(&'"') => {
                        chars.next();
                        column.push('"');
                    }
                    Some('"') => break,
                    Some(c) => column.push(c),
                    None => return Err("a quoted column isn't closed".to_owned()),
                }
            }
            match chars.next() {
                None => {
                    columns.push(column);
                    return Ok(columns);
                }
                Some(',') => {}
                Some(_) => return Err("a quoted column has more after its closing quote".to_owned()),
            }
        } else {
            loop {
                match chars.next() {
                    None => {
                        columns.push(column);
                        return Ok(columns);
                    }
                    Some(',') => break,
                    Some('"') => return Err("an unquoted column has a quote".to_owned()),
                    Some(c) => column.push(c),
                }
            }
        }
        columns.push(column);
    }
}

/// A URL-encoded key, decoded: `+` is a space, and every `%` starts an
/// escape; the result is UTF-8.
fn decode_key(encoded: &str) -> Result<String, String> {
    let bytes = encoded.as_bytes();
    for (i, _) in encoded.match_indices('%') {
        if !bytes.get(i + 1..i + 3).is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
            return Err("its key isn't URL-encoded".to_owned());
        }
    }
    percent_decode_str(&encoded.replace('+', " "))
        .decode_utf8()
        .map(|key| key.into_owned())
        .map_err(|_| "its key isn't UTF-8, URL-encoded".to_owned())
}

/// The complete lines at the start of `data` (without their endings), and
/// how many bytes they take (with them); if `last`, `data` is the rest of
/// the manifest, so its end ends a line too. At most `max` lines.
pub fn lines(data: &[u8], last: bool, max: usize) -> (Vec<&[u8]>, usize) {
    let mut lines = Vec::new();
    let mut consumed = 0;
    while lines.len() < max && consumed < data.len() {
        let rest = &data[consumed..];
        let (line, taken) = match rest.iter().position(|&b| b == b'\n') {
            Some(end) => (&rest[..end], end + 1),
            None if last => (rest, rest.len()),
            None => break,
        };
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        lines.push(line);
        consumed += taken;
    }
    (lines, consumed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: &[Field] = &[Field::Bucket, Field::Key];
    const VERSIONED: &[Field] = &[Field::Bucket, Field::Key, Field::VersionId];

    fn task(bucket: &str, key: &str, version_id: Option<&str>) -> Task {
        Task { bucket: bucket.to_owned(), key: key.to_owned(), version_id: version_id.map(str::to_owned) }
    }

    #[test]
    fn fields_name_a_bucket_and_a_key() {
        assert!(check_fields(FIELDS).is_ok());
        assert!(check_fields(&[Field::Ignore, Field::Key, Field::Bucket, Field::VersionId]).is_ok());
        assert!(check_fields(&[Field::Key]).is_err());
        assert!(check_fields(&[Field::Bucket, Field::Key, Field::Key]).is_err());
        assert!(check_fields(&[Field::Bucket, Field::Key, Field::VersionId, Field::VersionId]).is_err());
        assert_eq!(Field::parse("VersionId"), Some(Field::VersionId));
        assert_eq!(Field::parse("versionid"), None);
    }

    #[test]
    fn lines_are_parsed_as_their_fields_say() {
        assert_eq!(parse_line("b,photos/a.jpg", FIELDS), Ok(task("b", "photos/a.jpg", None)));
        assert_eq!(parse_line("b,a,v1", VERSIONED), Ok(task("b", "a", Some("v1"))));
        // An empty version ID is the current version.
        assert_eq!(parse_line("b,a,", VERSIONED), Ok(task("b", "a", None)));
        assert_eq!(parse_line("x,a,b", &[Field::Ignore, Field::Key, Field::Bucket]), Ok(task("b", "a", None)));
        // Quoted, as inventory reports' are.
        assert_eq!(parse_line(r#""b","a,b""c""#, FIELDS), Ok(task("b", "a,b\"c", None)));
        assert_eq!(parse_line(r#""b","""#, FIELDS).unwrap_err(), "its key is empty");
        // URL-encoded keys.
        assert_eq!(parse_line("b,my+photo%2B1%C3%A9.jpg", FIELDS), Ok(task("b", "my photo+1é.jpg", None)));
        assert!(parse_line("b,100%", FIELDS).is_err());
        assert!(parse_line("b,%FF", FIELDS).is_err());
    }

    #[test]
    fn bad_lines_are_refused() {
        assert!(parse_line("b", FIELDS).is_err());
        assert!(parse_line("b,a,c", FIELDS).is_err());
        assert!(parse_line(",a", FIELDS).is_err());
        assert!(parse_line("b,", FIELDS).is_err());
        assert!(parse_line(r#""b,a"#, FIELDS).is_err());
        assert!(parse_line(r#""b"x,a"#, FIELDS).is_err());
        assert!(parse_line(r#"b,a"b"#, FIELDS).is_err());
        assert!(parse_line(&format!("b,{}", "k".repeat(1025)), FIELDS).is_err());
        assert!(parse_line(&format!("b,{}", "k".repeat(1024)), FIELDS).is_ok());
    }

    #[test]
    fn lines_end_at_newlines_or_the_end() {
        let data = b"b,a\r\nb,c\nb,d";
        assert_eq!(lines(data, false, 10), (vec![&b"b,a"[..], b"b,c"], 9));
        assert_eq!(lines(data, true, 10), (vec![&b"b,a"[..], b"b,c", b"b,d"], 12));
        assert_eq!(lines(data, true, 1), (vec![&b"b,a"[..]], 5));
        assert_eq!(lines(b"", true, 10), (vec![], 0));
        assert_eq!(lines(b"b,a\n", true, 10), (vec![&b"b,a"[..]], 4));
        assert_eq!(lines(b"b,a", false, 10), (vec![], 0));
    }
}
