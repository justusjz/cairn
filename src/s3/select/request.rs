//! The `<SelectObjectContentRequest>` a SelectObjectContent sends.

use roxmltree::Node;

use super::SelectError;
use super::input::{CsvInput, HeaderInfo, JsonType};
use super::output::{CsvOutput, Output};

#[derive(Debug)]
pub struct SelectRequest {
    pub expression: String,
    pub input: Input,
    pub gzip: bool,
    /// The part of the object to read records from, if not all of it.
    pub scan_range: Option<ScanRange>,
    pub output: Output,
    /// Whether it asks for Progress events.
    pub progress: bool,
}

/// `ScanRange`: the records whose first byte is in the range are read, as
/// AWS's API reference has it ("A record is processed when its first byte
/// is contained by the range"), each to its end, even past the range's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRange {
    /// From byte `start` to byte `end` (inclusive), or to the end.
    From { start: u64, end: Option<u64> },
    /// The last `n` bytes (`n` > 0).
    Last(u64),
}

impl ScanRange {
    /// Its first and last byte (inclusive) in an object of `size` bytes:
    /// `None` if none of the object's bytes are in it.
    pub fn bytes(self, size: u64) -> Option<(u64, u64)> {
        let (start, end) = match self {
            ScanRange::From { start, end } => (start, end.unwrap_or(u64::MAX)),
            ScanRange::Last(n) => (size.saturating_sub(n), u64::MAX),
        };
        (start < size).then(|| (start, end.min(size - 1)))
    }
}

#[derive(Debug)]
pub enum Input {
    Csv(CsvInput),
    Json(JsonType),
    Parquet,
}

fn malformed() -> SelectError {
    SelectError::new(
        "MalformedXML",
        "The XML you provided was not well-formed or did not validate against our published schema.",
    )
}

fn invalid(code: &'static str, message: impl Into<String>) -> SelectError {
    SelectError::new(code, message)
}

fn not_implemented(what: &str) -> SelectError {
    SelectError::new(
        "NotImplemented",
        format!("{what} isn't supported by this server's S3 Select yet."),
    )
}

fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    node.children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

/// The text of `node`'s child `name`, as it is: a delimiter can be
/// whitespace. `None` if there's no such child, or it's empty.
fn raw<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    child(node, name)
        .and_then(|n| n.text())
        .filter(|t| !t.is_empty())
}

/// Likewise, trimmed, for a keyword or a number.
fn word<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    raw(node, name).map(str::trim).filter(|t| !t.is_empty())
}

/// A keyword, in capitals: S3 takes them in any case (AWS SDK for pandas
/// sends `Use` and `Lines`, as its documentation has them).
fn keyword(node: Node<'_, '_>, name: &str) -> Option<String> {
    word(node, name).map(str::to_ascii_uppercase)
}

fn boolean(node: Node<'_, '_>, name: &str) -> Result<bool, SelectError> {
    match word(node, name) {
        None => Ok(false),
        Some(t) if t.eq_ignore_ascii_case("true") => Ok(true),
        Some(t) if t.eq_ignore_ascii_case("false") => Ok(false),
        Some(_) => Err(malformed()),
    }
}

/// A delimiter, quote or escape `name`: `default` if it isn't given.
fn character(node: Node<'_, '_>, name: &str, default: &[u8]) -> Result<Vec<u8>, SelectError> {
    match raw(node, name) {
        None => Ok(default.to_vec()),
        // A character, as S3 Select takes them, or two (`\r\n`).
        Some(text) if text.chars().count() <= 2 => Ok(text.as_bytes().to_vec()),
        Some(_) => Err(invalid(
            "InvalidRequestParameter",
            format!("{name} must be a single character."),
        )),
    }
}

pub fn parse(body: &[u8]) -> Result<SelectRequest, SelectError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(invalid("EmptyRequestBody", "The request body is empty."));
    }
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let doc = roxmltree::Document::parse(text).map_err(|_| malformed())?;
    let root = doc.root_element();
    if root.tag_name().name() != "SelectObjectContentRequest" {
        return Err(malformed());
    }
    let missing = |name: &str| {
        invalid(
            "MissingRequiredParameter",
            format!("The request is missing {name}."),
        )
    };
    let expression = raw(root, "Expression")
        .ok_or_else(|| missing("Expression"))?
        .to_owned();
    match keyword(root, "ExpressionType").as_deref() {
        Some("SQL") => {}
        Some(_) => {
            return Err(invalid(
                "InvalidExpressionType",
                "The ExpressionType is invalid. Only SQL expressions are supported.",
            ));
        }
        None => return Err(missing("ExpressionType")),
    }
    let scan_range = match child(root, "ScanRange") {
        Some(node) => Some(scan_range(node)?),
        None => None,
    };
    let progress = match child(root, "RequestProgress") {
        Some(node) => boolean(node, "Enabled")?,
        None => false,
    };
    let input = child(root, "InputSerialization").ok_or_else(|| missing("InputSerialization"))?;
    let gzip = match keyword(input, "CompressionType").as_deref() {
        None | Some("NONE") => false,
        Some("GZIP") => true,
        Some("BZIP2") => return Err(not_implemented("BZIP2 compression")),
        Some(_) => {
            return Err(invalid(
                "InvalidCompressionFormat",
                "The file is not in a supported compression format. Only GZIP and BZIP2 are supported.",
            ));
        }
    };
    let formats: Vec<_> = input
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() != "CompressionType")
        .collect();
    let [format] = formats[..] else {
        return Err(invalid(
            "ObjectSerializationConflict",
            "InputSerialization must name exactly one format: CSV, JSON or Parquet.",
        ));
    };
    let mut quoted_delimiters = false;
    let input = match format.tag_name().name() {
        "CSV" => {
            quoted_delimiters = boolean(format, "AllowQuotedRecordDelimiter")?;
            let header = match keyword(format, "FileHeaderInfo").as_deref() {
                None | Some("NONE") => HeaderInfo::None,
                Some("IGNORE") => HeaderInfo::Ignore,
                Some("USE") => HeaderInfo::Use,
                Some(_) => {
                    return Err(invalid(
                        "InvalidFileHeaderInfo",
                        "The FileHeaderInfo is invalid. Only NONE, USE, and IGNORE are supported.",
                    ));
                }
            };
            let quote = character(format, "QuoteCharacter", b"\"")?;
            Input::Csv(CsvInput {
                header,
                field_delimiter: character(format, "FieldDelimiter", b",")?,
                record_delimiter: character(format, "RecordDelimiter", b"\n")?,
                quote_escape: character(format, "QuoteEscapeCharacter", &quote)?,
                quote,
                comments: Some(character(format, "Comments", b"#")?),
            })
        }
        "JSON" => Input::Json(match keyword(format, "Type").as_deref() {
            None | Some("DOCUMENT") => JsonType::Document,
            Some("LINES") => JsonType::Lines,
            Some(_) => {
                return Err(invalid(
                    "InvalidJsonType",
                    "The JsonType is invalid. Only DOCUMENT and LINES are supported.",
                ));
            }
        }),
        // Its columns are compressed, if anything is: never all of it.
        "Parquet" if gzip => {
            return Err(invalid(
                "InvalidCompressionFormat",
                "Parquet objects aren't compressed as a whole (their columns may be): CompressionType must be NONE.",
            ));
        }
        "Parquet" => Input::Parquet,
        _ => return Err(malformed()),
    };
    // As in S3: ranges only of what can be split into records without
    // reading from the start.
    if scan_range.is_some() {
        let splits = match &input {
            Input::Csv(_) => !quoted_delimiters,
            Input::Json(json) => *json == JsonType::Lines,
            // By its row groups.
            Input::Parquet => true,
        };
        if gzip || !splits {
            return Err(invalid(
                "UnsupportedScanRangeInput",
                "Scan range queries are not supported on this type of object: only on Parquet, uncompressed CSV (without AllowQuotedRecordDelimiter) and JSON LINES.",
            ));
        }
    }
    let output =
        child(root, "OutputSerialization").ok_or_else(|| missing("OutputSerialization"))?;
    let formats: Vec<_> = output.children().filter(|n| n.is_element()).collect();
    let [format] = formats[..] else {
        return Err(invalid(
            "ObjectSerializationConflict",
            "OutputSerialization must name exactly one format: CSV or JSON.",
        ));
    };
    let output = match format.tag_name().name() {
        "CSV" => {
            let quote = character(format, "QuoteCharacter", b"\"")?;
            Output::Csv(CsvOutput {
                field_delimiter: character(format, "FieldDelimiter", b",")?,
                record_delimiter: character(format, "RecordDelimiter", b"\n")?,
                quote_escape: character(format, "QuoteEscapeCharacter", &quote)?,
                quote,
                always_quote: match keyword(format, "QuoteFields").as_deref() {
                    None | Some("ASNEEDED") => false,
                    Some("ALWAYS") => true,
                    Some(_) => {
                        return Err(invalid(
                            "InvalidQuoteFields",
                            "The QuoteFields is invalid. Only ALWAYS and ASNEEDED are supported.",
                        ));
                    }
                },
            })
        }
        "JSON" => Output::Json {
            record_delimiter: character(format, "RecordDelimiter", b"\n")?,
        },
        _ => return Err(malformed()),
    };
    Ok(SelectRequest {
        expression,
        input,
        gzip,
        scan_range,
        output,
        progress,
    })
}

/// A `<ScanRange>`: a `Start`, an `End`, or both, `Start` no later than
/// `End`; only an `End` is the object's last `End` bytes.
fn scan_range(node: Node<'_, '_>) -> Result<ScanRange, SelectError> {
    let number = |name: &str| match word(node, name) {
        None => Ok(None),
        Some(text) => text.parse::<u64>().map(Some).map_err(|_| invalid_range()),
    };
    match (number("Start")?, number("End")?) {
        (None, None) | (None, Some(0)) => Err(invalid_range()),
        (None, Some(n)) => Ok(ScanRange::Last(n)),
        (Some(start), Some(end)) if start > end => Err(invalid_range()),
        (Some(start), end) => Ok(ScanRange::From { start, end }),
    }
}

fn invalid_range() -> SelectError {
    invalid(
        "InvalidScanRange",
        "The provided scan range is invalid: Start and End must be non-negative integers, at least one of them given, and Start no greater than End.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(input: &str, output: &str) -> String {
        format!(
            "<SelectObjectContentRequest xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Expression>SELECT * FROM S3Object s WHERE s._1 &lt; 3</Expression>\
             <ExpressionType>SQL</ExpressionType>\
             <RequestProgress><Enabled>true</Enabled></RequestProgress>\
             <InputSerialization>{input}</InputSerialization>\
             <OutputSerialization>{output}</OutputSerialization>\
             </SelectObjectContentRequest>"
        )
    }

    #[test]
    fn parses_csv_to_json() {
        let body = request(
            "<CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>\t</FieldDelimiter></CSV>\
             <CompressionType>GZIP</CompressionType>",
            "<JSON><RecordDelimiter>,</RecordDelimiter></JSON>",
        );
        let parsed = parse(body.as_bytes()).unwrap();
        assert_eq!(parsed.expression, "SELECT * FROM S3Object s WHERE s._1 < 3");
        assert!(parsed.gzip && parsed.progress);
        let Input::Csv(csv) = parsed.input else {
            panic!()
        };
        assert_eq!(csv.header, HeaderInfo::Use);
        assert_eq!(csv.field_delimiter, b"\t");
        assert_eq!(csv.record_delimiter, b"\n");
        assert!(
            matches!(parsed.output, Output::Json { record_delimiter } if record_delimiter == b",")
        );
    }

    #[test]
    fn refuses_what_it_does_not_take() {
        let code =
            |input: &str, output: &str| parse(request(input, output).as_bytes()).unwrap_err().code;
        let csv = "<CSV/>";
        assert_eq!(
            code("<Parquet/><CompressionType>GZIP</CompressionType>", csv),
            "InvalidCompressionFormat"
        );
        assert_eq!(
            code("<CSV/><CompressionType>BZIP2</CompressionType>", csv),
            "NotImplemented"
        );
        assert_eq!(
            code("<CSV/><CompressionType>ZIP</CompressionType>", csv),
            "InvalidCompressionFormat"
        );
        assert_eq!(code("<CSV/><JSON/>", csv), "ObjectSerializationConflict");
        assert_eq!(code("<JSON><Type>X</Type></JSON>", csv), "InvalidJsonType");
        assert_eq!(
            code("<CSV><FileHeaderInfo>X</FileHeaderInfo></CSV>", csv),
            "InvalidFileHeaderInfo"
        );
        assert_eq!(
            code(csv, "<CSV><QuoteFields>X</QuoteFields></CSV>"),
            "InvalidQuoteFields"
        );
        assert_eq!(
            code(csv, "<CSV><FieldDelimiter>abc</FieldDelimiter></CSV>"),
            "InvalidRequestParameter"
        );
        assert_eq!(parse(b"").unwrap_err().code, "EmptyRequestBody");
        assert_eq!(parse(b"<x/>").unwrap_err().code, "MalformedXML");
    }

    /// The ScanRange of a request with `range` and `input`, or its error's
    /// code.
    fn ranged(input: &str, range: &str) -> Result<ScanRange, &'static str> {
        let body = request(input, "<CSV/>").replace(
            "<InputSerialization>",
            &format!("<ScanRange>{range}</ScanRange><InputSerialization>"),
        );
        parse(body.as_bytes())
            .map(|r| r.scan_range.unwrap())
            .map_err(|e| e.code)
    }

    /// In any case, as S3 takes them.
    #[test]
    fn takes_keywords_in_any_case() {
        let body = request(
            "<CSV><FileHeaderInfo>Use</FileHeaderInfo></CSV><CompressionType>gzip</CompressionType>",
            "<CSV><QuoteFields>Always</QuoteFields></CSV>",
        )
        .replace(">SQL<", ">sql<");
        let parsed = parse(body.as_bytes()).unwrap();
        assert!(parsed.gzip);
        assert!(matches!(
            parsed.input,
            Input::Csv(CsvInput {
                header: HeaderInfo::Use,
                ..
            })
        ));
        assert!(matches!(
            parsed.output,
            Output::Csv(CsvOutput {
                always_quote: true,
                ..
            })
        ));
        let body = request("<JSON><Type>Lines</Type></JSON>", "<JSON/>");
        let parsed = parse(body.as_bytes()).unwrap();
        assert!(matches!(parsed.input, Input::Json(JsonType::Lines)));
    }

    #[test]
    fn parses_scan_ranges() {
        let csv = "<CSV/>";
        let lines = "<JSON><Type>LINES</Type></JSON>";
        let both = "<Start>1</Start><End>9</End>";
        let from = ScanRange::From {
            start: 1,
            end: Some(9),
        };
        assert_eq!(ranged(csv, both), Ok(from));
        assert_eq!(ranged(lines, both), Ok(from));
        assert_eq!(ranged(csv, "<End>5</End>"), Ok(ScanRange::Last(5)));
        assert_eq!(
            ranged(csv, "<Start>5</Start>"),
            Ok(ScanRange::From {
                start: 5,
                end: None
            })
        );
        assert_eq!(
            ranged(csv, "<Start>9</Start><End>9</End>").map(|_| ()),
            Ok(())
        );
        // What can't be split into records from the middle.
        let gzip = "<CSV/><CompressionType>GZIP</CompressionType>";
        let document = "<JSON><Type>DOCUMENT</Type></JSON>";
        let quoted = "<CSV><AllowQuotedRecordDelimiter>TRUE</AllowQuotedRecordDelimiter></CSV>";
        for input in [gzip, document, quoted] {
            assert_eq!(ranged(input, both), Err("UnsupportedScanRangeInput"));
        }
        for range in [
            "<Start>9</Start><End>1</End>",
            "<Start>-1</Start>",
            "<Start>x</Start>",
            "",
            "<End>0</End>",
        ] {
            assert_eq!(ranged(csv, range), Err("InvalidScanRange"), "{range}");
        }
    }

    #[test]
    fn scan_ranges_name_bytes() {
        let from = |start, end| ScanRange::From { start, end };
        assert_eq!(ScanRange::Last(5).bytes(100), Some((95, 99)));
        assert_eq!(ScanRange::Last(500).bytes(100), Some((0, 99)));
        assert_eq!(from(5, Some(500)).bytes(100), Some((5, 99)));
        assert_eq!(from(5, None).bytes(100), Some((5, 99)));
        assert_eq!(from(99, Some(99)).bytes(100), Some((99, 99)));
        assert_eq!(from(100, None).bytes(100), None);
        assert_eq!(ScanRange::Last(5).bytes(0), None);
    }
}
