//! The values S3 Select's SQL works with: what a CSV field (always a
//! string) or a JSON value is, and what expressions make of them.

use std::cmp::Ordering;
use std::fmt::Write;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use super::timestamp::Timestamp;

/// A value, as PartiQL (S3 Select's dialect) has them. `Missing` is what a
/// path that leads nowhere is (a column past a record's last, or a key a
/// JSON object doesn't have), which is unlike `Null`: it isn't written out.
#[derive(Clone, Debug)]
pub enum Value {
    Missing,
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Timestamp(Timestamp),
    List(Vec<Value>),
    /// A JSON object, its keys in their order.
    Struct(Vec<(String, Value)>),
}

impl Value {
    /// Whether it's `NULL` or `MISSING`, which most operations pass on.
    pub fn is_absent(&self) -> bool {
        matches!(self, Value::Missing | Value::Null)
    }

    /// As a number, if it is one, or a string that reads as one: CSV's
    /// fields are strings, which S3 Select compares with numbers as numbers.
    pub fn as_number(&self) -> Option<Number> {
        match self {
            Value::Int(i) => Some(Number::Int(*i)),
            Value::Float(f) => Some(Number::Float(*f)),
            Value::Str(s) => Number::parse(s),
            _ => None,
        }
    }

    /// Its text, for a CSV field, a concatenation, or a cast to a string:
    /// nothing for `NULL` and `MISSING`, JSON for a list or a struct.
    pub fn to_text(&self) -> String {
        match self {
            Value::Missing | Value::Null => String::new(),
            Value::Bool(b) => b.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => format_float(*f),
            Value::Str(s) => s.clone(),
            Value::Timestamp(t) => t.to_text(),
            Value::List(_) | Value::Struct(_) => {
                let mut out = String::new();
                self.write_json(&mut out);
                out
            }
        }
    }

    /// Writes it as JSON. (`MISSING` as `null`: where it's left out, the
    /// caller leaves it out.)
    pub fn write_json(&self, out: &mut String) {
        match self {
            Value::Missing | Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Value::Float(f) if f.is_finite() => out.push_str(&format_float(*f)),
            Value::Float(_) => out.push_str("null"),
            Value::Str(s) => write_json_string(s, out),
            Value::Timestamp(t) => write_json_string(&t.to_text(), out),
            Value::List(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Struct(fields) => {
                out.push('{');
                let mut first = true;
                for (name, value) in fields {
                    if matches!(value, Value::Missing) {
                        continue;
                    }
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    write_json_string(name, out);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

/// Writes `s` as a JSON string.
pub fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A float's text: as Rust writes it (the shortest that reads back the
/// same), but always with a fraction, so that it reads back as a float.
pub fn format_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    let text = f.to_string();
    if text.contains(['.', 'e', 'E']) {
        text
    } else {
        text + ".0"
    }
}

/// A number, for arithmetic and comparisons.
#[derive(Clone, Copy, Debug)]
pub enum Number {
    Int(i64),
    Float(f64),
}

impl Number {
    /// `s`, trimmed, if it reads as a number: an integer if it can be one.
    pub fn parse(s: &str) -> Option<Number> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(i) = s.parse::<i64>() {
            return Some(Number::Int(i));
        }
        // Rust reads "inf" and "nan", which aren't numbers here.
        let numeric = s
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
        match numeric {
            true => s.parse::<f64>().ok().map(Number::Float),
            false => None,
        }
    }

    pub fn as_f64(self) -> f64 {
        match self {
            Number::Int(i) => i as f64,
            Number::Float(f) => f,
        }
    }

    pub fn value(self) -> Value {
        match self {
            Number::Int(i) => Value::Int(i),
            Number::Float(f) => Value::Float(f),
        }
    }

    pub fn cmp(self, other: Number) -> Option<Ordering> {
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => Some(a.cmp(&b)),
            (a, b) => a.as_f64().partial_cmp(&b.as_f64()),
        }
    }
}

/// How `a` compares with `b`, if they can be compared: numbers (or strings
/// that read as numbers, against numbers) as numbers, strings as strings,
/// booleans as booleans, lists and structs by their items. `None` if either
/// is `NULL` or `MISSING`, or they're of kinds that don't compare.
pub fn compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Missing | Value::Null, _) | (_, Value::Missing | Value::Null) => None,
        (Value::Str(x), Value::Str(y)) => Some(x.cmp(y)),
        // Timestamps as the instants they are, and strings that are
        // timestamps (in CSV and JSON, they're strings) as timestamps.
        (Value::Timestamp(x), Value::Timestamp(y)) => Some(x.instant().cmp(&y.instant())),
        (Value::Timestamp(x), Value::Str(y)) => {
            Some(x.instant().cmp(&Timestamp::parse(y).ok()?.instant()))
        }
        (Value::Str(x), Value::Timestamp(y)) => {
            Some(Timestamp::parse(x).ok()?.instant().cmp(&y.instant()))
        }
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        (Value::Bool(x), Value::Str(y)) => parse_bool(y).map(|y| x.cmp(&y)),
        (Value::Str(x), Value::Bool(y)) => parse_bool(x).map(|x| x.cmp(y)),
        (Value::List(x), Value::List(y)) => {
            for (x, y) in x.iter().zip(y) {
                match compare(x, y)? {
                    Ordering::Equal => continue,
                    other => return Some(other),
                }
            }
            Some(x.len().cmp(&y.len()))
        }
        (Value::Struct(x), Value::Struct(y)) => {
            if x.len() != y.len() {
                return None;
            }
            for ((xn, xv), (yn, yv)) in x.iter().zip(y) {
                if xn != yn || compare(xv, yv)? != Ordering::Equal {
                    return None;
                }
            }
            Some(Ordering::Equal)
        }
        _ => a.as_number()?.cmp(b.as_number()?),
    }
}

/// `true` or `false`, in any case.
pub fn parse_bool(s: &str) -> Option<bool> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("true") {
        Some(true)
    } else if s.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// JSON, read straight into `Value`s, keeping objects' keys in order.
impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Int(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(match i64::try_from(v) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Float(v as f64),
        })
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::Float(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::Str(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::Str(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Deserialize::deserialize(d)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::List(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut fields = Vec::new();
        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            fields.push((key, value));
        }
        Ok(Value::Struct(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_keeps_key_order() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":[true,null,"x"],"c":1.5}"#).unwrap();
        let mut out = String::new();
        v.write_json(&mut out);
        assert_eq!(out, r#"{"b":1,"a":[true,null,"x"],"c":1.5}"#);
    }

    #[test]
    fn strings_compare_with_numbers_as_numbers() {
        let ten = Value::Str("10".into());
        assert_eq!(compare(&ten, &Value::Int(9)), Some(Ordering::Greater));
        assert_eq!(compare(&ten, &Value::Str("9".into())), Some(Ordering::Less));
        assert_eq!(compare(&Value::Str("x".into()), &Value::Int(9)), None);
        assert_eq!(compare(&Value::Null, &Value::Int(9)), None);
        assert_eq!(
            compare(&Value::Str(" 2.5 ".into()), &Value::Float(2.5)),
            Some(Ordering::Equal)
        );
    }

    #[test]
    fn timestamps_compare_as_instants() {
        let t = |s: &str| Value::Timestamp(Timestamp::parse(s).unwrap());
        let noon = t("2020-01-01T12:00Z");
        assert_eq!(
            compare(&noon, &t("2020-01-01T13:00+01:00")),
            Some(Ordering::Equal)
        );
        assert_eq!(compare(&noon, &t("2020T")), Some(Ordering::Greater));
        let text = Value::Str("2020-01-02T".into());
        assert_eq!(compare(&text, &noon), Some(Ordering::Greater));
        assert_eq!(compare(&noon, &Value::Str("noon".into())), None);
        assert_eq!(compare(&noon, &Value::Int(1)), None);
    }

    #[test]
    fn floats_read_back_as_floats() {
        assert_eq!(format_float(3.0), "3.0");
        assert_eq!(format_float(0.1), "0.1");
        assert_eq!(Number::parse("inf").map(|n| n.as_f64()), None);
    }
}
