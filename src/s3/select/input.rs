//! Splitting an object's (decompressed) bytes into records, as they arrive.

use super::SelectError;
use super::value::Value;

/// The longest record S3 Select reads (its documented limit: 1 MB).
pub const MAX_RECORD: usize = 1 << 20;

/// How a CSV object is read (`InputSerialization`'s `CSV`).
#[derive(Debug, Clone)]
pub struct CsvInput {
    pub header: HeaderInfo,
    pub field_delimiter: Vec<u8>,
    pub record_delimiter: Vec<u8>,
    pub quote: Vec<u8>,
    pub quote_escape: Vec<u8>,
    /// A record starting with it is skipped.
    pub comments: Option<Vec<u8>>,
}

impl Default for CsvInput {
    fn default() -> CsvInput {
        CsvInput {
            header: HeaderInfo::None,
            field_delimiter: b",".to_vec(),
            record_delimiter: b"\n".to_vec(),
            quote: b"\"".to_vec(),
            quote_escape: b"\"".to_vec(),
            comments: None,
        }
    }
}

/// `FileHeaderInfo`: what a CSV object's first record is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderInfo {
    /// A record like any other.
    None,
    /// A header, skipped.
    Ignore,
    /// A header, whose names name the columns.
    Use,
}

/// Whether `buf[at..]` starts with `pattern`: `None` if it can't be told
/// yet, as `buf` ends with a part of it and more is to come.
fn starts(buf: &[u8], at: usize, pattern: &[u8], eof: bool) -> Option<bool> {
    let rest = &buf[at..];
    if rest.len() >= pattern.len() {
        return Some(rest.starts_with(pattern));
    }
    if !eof && pattern.starts_with(rest) {
        return None;
    }
    Some(false)
}

/// What reading a record found.
pub enum Read<T> {
    /// A record, and where the next one starts.
    Record(T, usize),
    /// Something to skip (a comment, an empty line), and where the next
    /// record starts.
    Skip(usize),
    /// More bytes are needed (or, at the end, there's nothing more).
    More,
}

fn utf8(bytes: Vec<u8>) -> Result<String, SelectError> {
    String::from_utf8(bytes).map_err(|_| {
        SelectError::new(
            "InvalidTextEncoding",
            "The object isn't UTF-8: S3 Select reads UTF-8 only.",
        )
    })
}

impl CsvInput {
    /// Reads the record at `buf[at..]`. `eof` is whether `buf` holds the
    /// rest of the object.
    pub fn read(&self, buf: &[u8], at: usize, eof: bool) -> Result<Read<Vec<String>>, SelectError> {
        if at >= buf.len() {
            return Ok(Read::More);
        }
        // An empty line, which isn't a record.
        match starts(buf, at, &self.record_delimiter, eof) {
            None => return Ok(Read::More),
            Some(true) => return Ok(Read::Skip(at + self.record_delimiter.len())),
            Some(false) => {}
        }
        if self.record_delimiter == b"\n" && buf[at..].starts_with(b"\r\n") {
            return Ok(Read::Skip(at + 2));
        }
        if let Some(comments) = &self.comments {
            match starts(buf, at, comments, eof) {
                None => return Ok(Read::More),
                Some(true) => {
                    let mut i = at;
                    loop {
                        if i >= buf.len() {
                            return Ok(if eof { Read::Skip(i) } else { Read::More });
                        }
                        match starts(buf, i, &self.record_delimiter, eof) {
                            None => return Ok(Read::More),
                            Some(true) => return Ok(Read::Skip(i + self.record_delimiter.len())),
                            Some(false) => i += 1,
                        }
                    }
                }
                Some(false) => {}
            }
        }
        let mut fields = Vec::new();
        let mut field = Vec::new();
        let mut quoted = false;
        // Whether the field has been quoted: the quote can only open one.
        let mut field_start = true;
        let mut i = at;
        let unterminated = || {
            SelectError::new(
                "CSVParsingError",
                "The object has a quoted field that isn't closed.",
            )
        };
        loop {
            if i >= buf.len() {
                if !eof {
                    return Ok(Read::More);
                }
                if quoted {
                    return Err(unterminated());
                }
                break;
            }
            if quoted {
                // An escaped quote: the escape and a quote (doubled, by
                // default).
                let escape = &self.quote_escape;
                match starts(buf, i, escape, eof) {
                    None => return Ok(Read::More),
                    Some(true) => match starts(buf, i + escape.len(), &self.quote, eof) {
                        None => return Ok(Read::More),
                        Some(true) => {
                            field.extend_from_slice(&self.quote);
                            i += escape.len() + self.quote.len();
                            continue;
                        }
                        Some(false) => {}
                    },
                    Some(false) => {}
                }
                match starts(buf, i, &self.quote, eof) {
                    None => return Ok(Read::More),
                    Some(true) => {
                        quoted = false;
                        i += self.quote.len();
                    }
                    Some(false) => {
                        field.push(buf[i]);
                        i += 1;
                    }
                }
                continue;
            }
            match starts(buf, i, &self.field_delimiter, eof) {
                None => return Ok(Read::More),
                Some(true) => {
                    fields.push(utf8(std::mem::take(&mut field))?);
                    field_start = true;
                    i += self.field_delimiter.len();
                    continue;
                }
                Some(false) => {}
            }
            match starts(buf, i, &self.record_delimiter, eof) {
                None => return Ok(Read::More),
                Some(true) => {
                    i += self.record_delimiter.len();
                    // A Windows line end, with the default delimiter.
                    if self.record_delimiter == b"\n" && field.last() == Some(&b'\r') {
                        field.pop();
                    }
                    fields.push(utf8(field)?);
                    return Ok(Read::Record(fields, i));
                }
                Some(false) => {}
            }
            if field_start && !self.quote.is_empty() {
                match starts(buf, i, &self.quote, eof) {
                    None => return Ok(Read::More),
                    Some(true) => {
                        quoted = true;
                        field_start = false;
                        i += self.quote.len();
                        continue;
                    }
                    Some(false) => {}
                }
            }
            field_start = false;
            field.push(buf[i]);
            i += 1;
        }
        // The last record, without a delimiter after it.
        if self.record_delimiter == b"\n" && field.last() == Some(&b'\r') {
            field.pop();
        }
        fields.push(utf8(field)?);
        Ok(Read::Record(fields, i))
    }
}

/// How a JSON object is read (`InputSerialization`'s `JSON`'s `Type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonType {
    /// One value per line.
    Lines,
    /// Values one after another, however laid out.
    Document,
}

fn json_error(e: serde_json::Error) -> SelectError {
    SelectError::new(
        "JSONParsingError",
        format!("The object isn't valid JSON: {e}."),
    )
}

impl JsonType {
    /// Reads the record at `buf[at..]`.
    pub fn read(self, buf: &[u8], at: usize, eof: bool) -> Result<Read<Value>, SelectError> {
        let rest = &buf[at..];
        let blank = rest
            .iter()
            .position(|b| !b.is_ascii_whitespace())
            .unwrap_or(rest.len());
        // Whitespace (empty lines among them) between records.
        if blank > 0 {
            return Ok(Read::Skip(at + blank));
        }
        if rest.is_empty() {
            return Ok(Read::More);
        }
        match self {
            JsonType::Lines => {
                let line = match rest.iter().position(|b| *b == b'\n') {
                    Some(n) => &rest[..n],
                    None if eof => rest,
                    None => return Ok(Read::More),
                };
                let value: Value = serde_json::from_slice(line).map_err(json_error)?;
                let next = at + line.len() + usize::from(line.len() < rest.len());
                Ok(Read::Record(value, next))
            }
            JsonType::Document => {
                let mut values = serde_json::Deserializer::from_slice(rest).into_iter::<Value>();
                match values.next() {
                    // A number at the end may go on in what's to come.
                    Some(Ok(_)) if values.byte_offset() == rest.len() && !eof => Ok(Read::More),
                    Some(Ok(value)) => Ok(Read::Record(value, at + values.byte_offset())),
                    Some(Err(e)) if e.is_eof() && !eof => Ok(Read::More),
                    Some(Err(e)) => Err(json_error(e)),
                    None => Ok(Read::Skip(buf.len())),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All of `input`'s records, fed `step` bytes at a time.
    fn records(csv: &CsvInput, input: &[u8], step: usize) -> Result<Vec<Vec<String>>, SelectError> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let mut fed = 0;
        let mut at = 0;
        loop {
            let eof = fed == input.len();
            match csv.read(&buf, at, eof)? {
                Read::Record(fields, next) => {
                    out.push(fields);
                    at = next;
                }
                Read::Skip(next) => at = next,
                Read::More if eof => return Ok(out),
                Read::More => {
                    let end = (fed + step).min(input.len());
                    buf.extend_from_slice(&input[fed..end]);
                    fed = end;
                }
            }
        }
    }

    #[test]
    fn reads_csv_however_it_arrives() {
        let input = b"a,b,c\r\n\"x, \"\"y\"\"\",2,\n\n# no\n\"multi\nline\",3,\"\"\nlast,4,z";
        let csv = CsvInput {
            comments: Some(b"#".to_vec()),
            ..CsvInput::default()
        };
        let want: Vec<Vec<String>> = vec![
            vec!["a".into(), "b".into(), "c".into()],
            vec!["x, \"y\"".into(), "2".into(), "".into()],
            vec!["multi\nline".into(), "3".into(), "".into()],
            vec!["last".into(), "4".into(), "z".into()],
        ];
        for step in [1, 2, 3, 7, 1000] {
            assert_eq!(records(&csv, input, step).unwrap(), want, "{step}");
        }
    }

    #[test]
    fn reads_csv_with_other_delimiters() {
        let csv = CsvInput {
            field_delimiter: b"\t".to_vec(),
            record_delimiter: b"||".to_vec(),
            quote: b"'".to_vec(),
            quote_escape: b"\\".to_vec(),
            ..CsvInput::default()
        };
        let input = b"a\t'b\\'s|| tab\t'||c\td";
        let want: Vec<Vec<String>> = vec![
            vec!["a".into(), "b's|| tab\t".into()],
            vec!["c".into(), "d".into()],
        ];
        for step in [1, 2, 5, 100] {
            assert_eq!(records(&csv, input, step).unwrap(), want, "{step}");
        }
    }

    #[test]
    fn refuses_bad_csv() {
        let csv = CsvInput::default();
        assert_eq!(
            records(&csv, b"\"open", 3).unwrap_err().code,
            "CSVParsingError"
        );
        assert_eq!(
            records(&csv, b"\xff\n", 3).unwrap_err().code,
            "InvalidTextEncoding"
        );
    }

    fn json(ty: JsonType, input: &[u8], step: usize) -> Result<Vec<String>, SelectError> {
        let mut out = Vec::new();
        let mut buf = Vec::new();
        let (mut fed, mut at) = (0, 0);
        loop {
            let eof = fed == input.len();
            match ty.read(&buf, at, eof)? {
                Read::Record(value, next) => {
                    out.push(value.to_text());
                    at = next;
                }
                Read::Skip(next) => at = next,
                Read::More if eof => return Ok(out),
                Read::More => {
                    let end = (fed + step).min(input.len());
                    buf.extend_from_slice(&input[fed..end]);
                    fed = end;
                }
            }
        }
    }

    #[test]
    fn reads_json() {
        let lines = b"{\"a\":1}\n\n  {\"a\":[2]}\r\n{\"a\":\"x\"}";
        for step in [1, 4, 100] {
            assert_eq!(
                json(JsonType::Lines, lines, step).unwrap(),
                [r#"{"a":1}"#, r#"{"a":[2]}"#, r#"{"a":"x"}"#]
            );
        }
        let document = b"{\"a\":\n1} {\"b\":\n  2}\n12345 ";
        for step in [1, 4, 100] {
            assert_eq!(
                json(JsonType::Document, document, step).unwrap(),
                [r#"{"a":1}"#, r#"{"b":2}"#, "12345"]
            );
        }
        assert_eq!(
            json(JsonType::Lines, b"{\"a\":\n1}", 100).unwrap_err().code,
            "JSONParsingError"
        );
    }
}
