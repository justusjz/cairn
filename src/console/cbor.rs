//! The little of CBOR (RFC 8949) that WebAuthn needs: decoding the
//! attestation object and COSE keys, which authenticators encode in CTAP2's
//! canonical form. Definite lengths only (CTAP2 uses no others); no floats
//! or tags, which nothing WebAuthn sends Cairn contains. Strict: anything
//! else is an error, rather than skipped.

/// A decoded CBOR value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// An integer: unsigned (major type 0) or negative (1), as i128 so that
    /// both fit.
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// A map's entries, in their order.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// The value of `key` in a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_int(&self, key: i128) -> Option<&Value> {
        self.get(&Value::Int(key))
    }

    pub fn get_text(&self, key: &str) -> Option<&Value> {
        self.get(&Value::Text(key.to_owned()))
    }

    pub fn as_int(&self) -> Option<i128> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
}

/// Why bytes aren't CBOR that Cairn reads.
#[derive(Debug, PartialEq)]
pub struct Malformed(pub &'static str);

/// How deep values may nest: WebAuthn's go three or four levels down.
const MAX_DEPTH: usize = 16;

/// Decodes the one value at the start of `bytes`, and says how many bytes it
/// took (the authenticator data has more after its COSE key, sometimes).
pub fn decode_prefix(bytes: &[u8]) -> Result<(Value, usize), Malformed> {
    let mut reader = Reader { bytes, at: 0 };
    let value = reader.value(0)?;
    Ok((value, reader.at))
}

/// Decodes `bytes`, which must be exactly one value.
pub fn decode(bytes: &[u8]) -> Result<Value, Malformed> {
    let (value, used) = decode_prefix(bytes)?;
    if used != bytes.len() {
        return Err(Malformed("trailing bytes after the CBOR value"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.bytes.len()).ok_or(Malformed("truncated CBOR"))?;
        let taken = &self.bytes[self.at..end];
        self.at = end;
        Ok(taken)
    }

    /// The argument of a head whose additional information is `info`.
    fn argument(&mut self, info: u8) -> Result<u64, Malformed> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(Malformed("indefinite or reserved CBOR length")),
        })
    }

    /// A length, which can't be more than the bytes left (each item takes at
    /// least one), so that a forged one can't make Cairn allocate.
    fn length(&mut self, info: u8) -> Result<usize, Malformed> {
        let n = self.argument(info)?;
        let left = (self.bytes.len() - self.at) as u64;
        if n > left {
            return Err(Malformed("truncated CBOR"));
        }
        Ok(n as usize)
    }

    fn value(&mut self, depth: usize) -> Result<Value, Malformed> {
        if depth > MAX_DEPTH {
            return Err(Malformed("CBOR nested too deep"));
        }
        let head = self.take(1)?[0];
        let (major, info) = (head >> 5, head & 0x1f);
        Ok(match major {
            0 => Value::Int(i128::from(self.argument(info)?)),
            1 => Value::Int(-1 - i128::from(self.argument(info)?)),
            2 => {
                let n = self.length(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.length(info)?;
                let text = std::str::from_utf8(self.take(n)?).map_err(|_| Malformed("CBOR text isn't UTF-8"))?;
                Value::Text(text.to_owned())
            }
            4 => {
                let n = self.length(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.length(info)?;
                let mut entries: Vec<(Value, Value)> = Vec::with_capacity(n);
                for _ in 0..n {
                    let key = self.value(depth + 1)?;
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(Malformed("duplicate key in a CBOR map"));
                    }
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Value::Map(entries)
            }
            7 => match info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                _ => return Err(Malformed("unsupported CBOR simple value or float")),
            },
            _ => return Err(Malformed("CBOR tags aren't supported")),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encodes `value` (for tests: building authenticators' responses).
    pub fn encode(value: &Value) -> Vec<u8> {
        fn head(out: &mut Vec<u8>, major: u8, n: u64) {
            let major = major << 5;
            match n {
                0..=23 => out.push(major | n as u8),
                24..=0xff => out.extend([major | 24, n as u8]),
                0x100..=0xffff => {
                    out.push(major | 25);
                    out.extend((n as u16).to_be_bytes());
                }
                0x1_0000..=0xffff_ffff => {
                    out.push(major | 26);
                    out.extend((n as u32).to_be_bytes());
                }
                _ => {
                    out.push(major | 27);
                    out.extend(n.to_be_bytes());
                }
            }
        }
        fn go(out: &mut Vec<u8>, value: &Value) {
            match value {
                Value::Int(i) if *i >= 0 => head(out, 0, *i as u64),
                Value::Int(i) => head(out, 1, (-1 - *i) as u64),
                Value::Bytes(b) => {
                    head(out, 2, b.len() as u64);
                    out.extend(b);
                }
                Value::Text(t) => {
                    head(out, 3, t.len() as u64);
                    out.extend(t.as_bytes());
                }
                Value::Array(items) => {
                    head(out, 4, items.len() as u64);
                    items.iter().for_each(|i| go(out, i));
                }
                Value::Map(entries) => {
                    head(out, 5, entries.len() as u64);
                    for (k, v) in entries {
                        go(out, k);
                        go(out, v);
                    }
                }
                Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
                Value::Null => out.push(0xf6),
            }
        }
        let mut out = Vec::new();
        go(&mut out, value);
        out
    }

    #[test]
    fn decodes_rfc_8949_examples() {
        let cases: &[(&str, Value)] = &[
            ("00", Value::Int(0)),
            ("17", Value::Int(23)),
            ("1818", Value::Int(24)),
            ("1903e8", Value::Int(1000)),
            ("1bffffffffffffffff", Value::Int(18446744073709551615)),
            ("3bffffffffffffffff", Value::Int(-18446744073709551616)),
            ("20", Value::Int(-1)),
            ("3903e7", Value::Int(-1000)),
            ("4401020304", Value::Bytes(vec![1, 2, 3, 4])),
            ("6449455446", Value::Text("IETF".into())),
            ("83010203", Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)])),
            (
                "a201020304",
                Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(4))]),
            ),
            ("f5", Value::Bool(true)),
            ("f6", Value::Null),
        ];
        for (hex, value) in cases {
            let bytes = hex_bytes(hex);
            assert_eq!(decode(&bytes).as_ref(), Ok(value), "{hex}");
            assert_eq!(encode(value), bytes, "{hex}");
        }
    }

    #[test]
    fn refuses_what_it_doesnt_read() {
        for hex in [
            "",           // nothing
            "5f",         // indefinite byte string
            "9f01ff",     // indefinite array
            "f93c00",     // a float
            "c11a514b67b0", // a tag
            "44010203",   // truncated
            "5bffffffffffffffff", // a length past the end
            "a201020103", // a duplicate key
            "0000",       // trailing bytes
            "62c328",     // invalid UTF-8
        ] {
            assert!(decode(&hex_bytes(hex)).is_err(), "{hex}");
        }
        // Nested past the limit.
        let deep = [vec![0x81; MAX_DEPTH + 1], vec![0x00]].concat();
        assert!(decode(&deep).is_err());
        let ok = [vec![0x81; MAX_DEPTH], vec![0x00]].concat();
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn says_how_much_a_prefix_took() {
        let bytes = hex_bytes("a10102ffff");
        let (value, used) = decode_prefix(&bytes).unwrap();
        assert_eq!(value, Value::Map(vec![(Value::Int(1), Value::Int(2))]));
        assert_eq!(used, 3);
    }

    pub fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }
}
