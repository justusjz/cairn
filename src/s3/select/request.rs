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
    pub output: Output,
    /// Whether it asks for Progress events.
    pub progress: bool,
}

#[derive(Debug)]
pub enum Input {
    Csv(CsvInput),
    Json(JsonType),
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
    match word(root, "ExpressionType") {
        Some("SQL") => {}
        Some(_) => {
            return Err(invalid(
                "InvalidExpressionType",
                "The ExpressionType is invalid. Only SQL expressions are supported.",
            ));
        }
        None => return Err(missing("ExpressionType")),
    }
    if child(root, "ScanRange").is_some() {
        return Err(not_implemented("ScanRange"));
    }
    let progress = match child(root, "RequestProgress") {
        Some(node) => boolean(node, "Enabled")?,
        None => false,
    };
    let input = child(root, "InputSerialization").ok_or_else(|| missing("InputSerialization"))?;
    let gzip = match word(input, "CompressionType") {
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
    let input = match format.tag_name().name() {
        "CSV" => {
            let header = match word(format, "FileHeaderInfo") {
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
        "JSON" => Input::Json(match word(format, "Type") {
            None | Some("DOCUMENT") => JsonType::Document,
            Some("LINES") => JsonType::Lines,
            Some(_) => {
                return Err(invalid(
                    "InvalidJsonType",
                    "The JsonType is invalid. Only DOCUMENT and LINES are supported.",
                ));
            }
        }),
        "Parquet" => return Err(not_implemented("Parquet input")),
        _ => return Err(malformed()),
    };
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
                always_quote: match word(format, "QuoteFields") {
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
        output,
        progress,
    })
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
        assert_eq!(code("<Parquet/>", csv), "NotImplemented");
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
}
