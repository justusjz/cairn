//! Writing the records a query selects (`OutputSerialization`).

use super::value::Value;

#[derive(Debug, Clone)]
pub enum Output {
    Csv(CsvOutput),
    Json { record_delimiter: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct CsvOutput {
    pub field_delimiter: Vec<u8>,
    pub record_delimiter: Vec<u8>,
    pub quote: Vec<u8>,
    pub quote_escape: Vec<u8>,
    /// `QuoteFields` `ALWAYS`; else `ASNEEDED`.
    pub always_quote: bool,
}

impl Default for CsvOutput {
    fn default() -> CsvOutput {
        CsvOutput {
            field_delimiter: b",".to_vec(),
            record_delimiter: b"\n".to_vec(),
            quote: b"\"".to_vec(),
            quote_escape: b"\"".to_vec(),
            always_quote: false,
        }
    }
}

impl Output {
    /// Writes a record of `fields` (by their names, for JSON) to `out`.
    pub fn write(&self, fields: &[(String, Value)], out: &mut Vec<u8>) {
        match self {
            Output::Csv(csv) => {
                for (i, (_, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.extend_from_slice(&csv.field_delimiter);
                    }
                    csv.field(&value.to_text(), out);
                }
                out.extend_from_slice(&csv.record_delimiter);
            }
            Output::Json { record_delimiter } => {
                let mut text = String::from("{");
                let mut first = true;
                for (name, value) in fields {
                    // A path that led nowhere isn't written, as in S3 Select.
                    if matches!(value, Value::Missing) {
                        continue;
                    }
                    if !first {
                        text.push(',');
                    }
                    first = false;
                    super::value::write_json_string(name, &mut text);
                    text.push(':');
                    value.write_json(&mut text);
                }
                text.push('}');
                out.extend_from_slice(text.as_bytes());
                out.extend_from_slice(record_delimiter);
            }
        }
    }
}

impl CsvOutput {
    fn field(&self, text: &str, out: &mut Vec<u8>) {
        let bytes = text.as_bytes();
        let contains = |pattern: &[u8]| {
            !pattern.is_empty() && bytes.windows(pattern.len()).any(|w| w == pattern)
        };
        let needs = self.always_quote
            || contains(&self.field_delimiter)
            || contains(&self.record_delimiter)
            || contains(&self.quote)
            || bytes.contains(&b'\n')
            || bytes.contains(&b'\r');
        if !needs {
            out.extend_from_slice(bytes);
            return;
        }
        out.extend_from_slice(&self.quote);
        let mut i = 0;
        while i < bytes.len() {
            if !self.quote.is_empty() && bytes[i..].starts_with(&self.quote) {
                out.extend_from_slice(&self.quote_escape);
                out.extend_from_slice(&self.quote);
                i += self.quote.len();
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        out.extend_from_slice(&self.quote);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Vec<(String, Value)> {
        vec![
            ("a".into(), Value::Str("plain".into())),
            ("b".into(), Value::Str("x,\"y\"".into())),
            ("c".into(), Value::Missing),
            ("d".into(), Value::Null),
            ("e".into(), Value::Int(3)),
            ("f".into(), Value::Float(1.5)),
        ]
    }

    #[test]
    fn writes_csv() {
        let mut out = Vec::new();
        Output::Csv(CsvOutput::default()).write(&row(), &mut out);
        assert_eq!(out, b"plain,\"x,\"\"y\"\"\",,,3,1.5\n");
        let mut out = Vec::new();
        let always = CsvOutput {
            always_quote: true,
            field_delimiter: b"\t".to_vec(),
            ..CsvOutput::default()
        };
        Output::Csv(always).write(&row()[..2], &mut out);
        assert_eq!(out, b"\"plain\"\t\"x,\"\"y\"\"\"\n");
    }

    #[test]
    fn writes_json() {
        let mut out = Vec::new();
        let json = Output::Json {
            record_delimiter: b"\n".to_vec(),
        };
        json.write(&row(), &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\"a\":\"plain\",\"b\":\"x,\\\"y\\\"\",\"d\":null,\"e\":3,\"f\":1.5}\n"
        );
    }
}
