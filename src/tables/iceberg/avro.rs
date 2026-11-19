//! Avro's object container files, read: what Iceberg writes its manifest
//! lists and manifests as, which maintenance reads the files of a table
//! from (see `maintenance`). Only reading, of the codecs Iceberg's writers
//! use (`null`, `deflate`, `snappy`), into JSON values, by the file's own
//! schema: enough to find the paths in them, without a library for all of
//! Avro.

use std::collections::HashMap;
use std::io::Read as _;

use serde_json::{Map, Value};

/// Why a file couldn't be read.
pub type Error = String;

const MAGIC: &[u8; 4] = b"Obj\x01";

/// The most a block may hold, decompressed: a manifest's blocks are far
/// smaller.
const MAX_BLOCK: u64 = 256 << 20;

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.data.len() < n {
            return Err("the file ends early".into());
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    /// A zigzag-encoded variable-length long (an int's too).
    fn long(&mut self) -> Result<i64, Error> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let byte = self.take(1)?[0];
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok((value >> 1) as i64 ^ -((value & 1) as i64));
            }
        }
        Err("a number is too long".into())
    }

    fn length(&mut self) -> Result<usize, Error> {
        match self.long()? {
            n if n >= 0 => Ok(n as usize),
            _ => Err("a negative length".into()),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = self.length()?;
        self.take(n)
    }

    fn string(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| "a string isn't UTF-8".into())
    }

    /// A block's count of items (an array's or map's), skipping its size.
    fn block_count(&mut self) -> Result<usize, Error> {
        let count = self.long()?;
        if count < 0 {
            self.long()?;
            return Ok(count.unsigned_abs() as usize);
        }
        Ok(count as usize)
    }
}

/// Named types, by their names (full and short).
type Names = HashMap<String, Value>;

fn register(schema: &Value, namespace: Option<&str>, names: &mut Names) {
    match schema {
        Value::Object(object) => {
            let ns = object
                .get("namespace")
                .and_then(Value::as_str)
                .or(namespace);
            if let Some(name) = object.get("name").and_then(Value::as_str)
                && matches!(
                    object.get("type").and_then(Value::as_str),
                    Some("record" | "error" | "enum" | "fixed")
                )
            {
                names.insert(name.to_owned(), schema.clone());
                if let Some(ns) = ns {
                    names.insert(format!("{ns}.{name}"), schema.clone());
                }
                if let Some((_, short)) = name.rsplit_once('.') {
                    names.insert(short.to_owned(), schema.clone());
                }
            }
            for field in object
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(t) = field.get("type") {
                    register(t, ns, names);
                }
            }
            for key in ["items", "values"] {
                if let Some(t) = object.get(key) {
                    register(t, ns, names);
                }
            }
            if let Some(t) = object.get("type").filter(|t| !t.is_string()) {
                register(t, ns, names);
            }
        }
        Value::Array(branches) => {
            for branch in branches {
                register(branch, namespace, names);
            }
        }
        _ => {}
    }
}

/// A value of `schema`, from `reader`.
fn decode(
    schema: &Value,
    reader: &mut Reader,
    names: &Names,
    depth: usize,
) -> Result<Value, Error> {
    if depth > 64 {
        return Err("the schema nests too deeply".into());
    }
    match schema {
        Value::String(name) => match name.as_str() {
            "null" => Ok(Value::Null),
            "boolean" => Ok(Value::Bool(reader.take(1)?[0] != 0)),
            "int" | "long" => Ok(Value::from(reader.long()?)),
            "float" => {
                let b = reader.take(4)?;
                Ok(Value::from(
                    f32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64
                ))
            }
            "double" => {
                let b = reader.take(8)?;
                Ok(Value::from(f64::from_le_bytes(
                    b.try_into().expect("8 bytes"),
                )))
            }
            // Bytes aren't needed: only skipped.
            "bytes" => reader.bytes().map(|_| Value::Null),
            "string" => reader.string().map(Value::String),
            other => {
                let named = names
                    .get(other)
                    .ok_or_else(|| format!("unknown type {other}"))?;
                decode(named, reader, names, depth + 1)
            }
        },
        Value::Array(branches) => {
            let index = reader.long()?;
            let branch = usize::try_from(index)
                .ok()
                .and_then(|i| branches.get(i))
                .ok_or("a union's branch isn't one")?;
            decode(branch, reader, names, depth + 1)
        }
        Value::Object(object) => match object.get("type") {
            Some(Value::String(t)) => match t.as_str() {
                "record" | "error" => {
                    let mut out = Map::new();
                    for field in object
                        .get("fields")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let name = field.get("name").and_then(Value::as_str).unwrap_or("");
                        let t = field.get("type").ok_or("a field has no type")?;
                        out.insert(name.to_owned(), decode(t, reader, names, depth + 1)?);
                    }
                    Ok(Value::Object(out))
                }
                "enum" => {
                    let index = reader.long()?;
                    let symbol = object
                        .get("symbols")
                        .and_then(Value::as_array)
                        .and_then(|s| s.get(index as usize))
                        .cloned()
                        .unwrap_or(Value::Null);
                    Ok(symbol)
                }
                "array" => {
                    let items = object.get("items").ok_or("an array has no items")?;
                    let mut out = Vec::new();
                    loop {
                        let count = reader.block_count()?;
                        if count == 0 {
                            break;
                        }
                        for _ in 0..count {
                            out.push(decode(items, reader, names, depth + 1)?);
                        }
                    }
                    Ok(Value::Array(out))
                }
                "map" => {
                    let values = object.get("values").ok_or("a map has no values")?;
                    let mut out = Map::new();
                    loop {
                        let count = reader.block_count()?;
                        if count == 0 {
                            break;
                        }
                        for _ in 0..count {
                            let key = reader.string()?;
                            out.insert(key, decode(values, reader, names, depth + 1)?);
                        }
                    }
                    Ok(Value::Object(out))
                }
                "fixed" => {
                    let size = object
                        .get("size")
                        .and_then(Value::as_u64)
                        .ok_or("a fixed has no size")?;
                    reader.take(size as usize).map(|_| Value::Null)
                }
                // A primitive, with attributes (a logical type, say).
                _ => decode(&Value::String(t.clone()), reader, names, depth + 1),
            },
            Some(inner) => decode(inner, reader, names, depth + 1),
            None => Err("a schema has no type".into()),
        },
        _ => Err("a schema isn't one".into()),
    }
}

/// The records of the object container file `file`.
pub fn records(file: &[u8]) -> Result<Vec<Value>, Error> {
    let mut reader = Reader { data: file };
    if reader.take(4)? != MAGIC {
        return Err("it isn't an Avro file".into());
    }
    let mut metadata = HashMap::new();
    loop {
        let count = reader.block_count()?;
        if count == 0 {
            break;
        }
        for _ in 0..count {
            let key = reader.string()?;
            let value = reader.bytes()?.to_vec();
            metadata.insert(key, value);
        }
    }
    let sync = reader.take(16)?;
    let schema: Value = metadata
        .get("avro.schema")
        .and_then(|s| serde_json::from_slice(s).ok())
        .ok_or("it has no schema")?;
    let codec = metadata
        .get("avro.codec")
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .unwrap_or_else(|| "null".to_owned());
    let mut names = Names::new();
    register(&schema, None, &mut names);
    let mut out = Vec::new();
    while !reader.data.is_empty() {
        let count = reader.length()?;
        let block = reader.bytes()?;
        if reader.take(16)? != sync {
            return Err("a block's sync marker isn't the file's".into());
        }
        let data = match codec.as_str() {
            "null" => block.to_vec(),
            "deflate" => {
                let mut data = Vec::new();
                flate2::read::DeflateDecoder::new(block)
                    .take(MAX_BLOCK)
                    .read_to_end(&mut data)
                    .map_err(|e| format!("a block doesn't inflate: {e}"))?;
                data
            }
            "snappy" => {
                // The block's snappy data, then its CRC-32 (big-endian).
                let compressed = &block[..block.len().saturating_sub(4)];
                let size = snap::raw::decompress_len(compressed)
                    .map_err(|e| format!("a block isn't snappy: {e}"))?;
                if size as u64 > MAX_BLOCK {
                    return Err("a block is too large".into());
                }
                snap::raw::Decoder::new()
                    .decompress_vec(compressed)
                    .map_err(|e| format!("a block isn't snappy: {e}"))?
            }
            other => return Err(format!("its codec {other} isn't supported")),
        };
        let mut block_reader = Reader { data: &data };
        for _ in 0..count {
            out.push(decode(&schema, &mut block_reader, &names, 0)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    fn long(out: &mut Vec<u8>, n: i64) {
        let mut v = ((n << 1) ^ (n >> 63)) as u64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    fn string(out: &mut Vec<u8>, s: &str) {
        long(out, s.len() as i64);
        out.extend_from_slice(s.as_bytes());
    }

    /// An object container file of `schema`, with blocks of encoded records
    /// (`blocks`: count, bytes), in `codec`.
    pub(crate) fn file(schema: &Value, codec: &str, blocks: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        long(&mut out, 2);
        string(&mut out, "avro.schema");
        string(&mut out, &schema.to_string());
        string(&mut out, "avro.codec");
        string(&mut out, codec);
        long(&mut out, 0);
        let sync = [7u8; 16];
        out.extend_from_slice(&sync);
        for (count, data) in blocks {
            let data = match codec {
                "deflate" => {
                    use std::io::Write as _;
                    let mut e = flate2::write::DeflateEncoder::new(
                        Vec::new(),
                        flate2::Compression::default(),
                    );
                    e.write_all(data).unwrap();
                    e.finish().unwrap()
                }
                "snappy" => {
                    let mut c = snap::raw::Encoder::new().compress_vec(data).unwrap();
                    c.extend_from_slice(&crc32fast::hash(data).to_be_bytes());
                    c
                }
                _ => data.clone(),
            };
            long(&mut out, *count);
            long(&mut out, data.len() as i64);
            out.extend_from_slice(&data);
            out.extend_from_slice(&sync);
        }
        out
    }

    /// A manifest entry, as Iceberg's (trimmed): a status, and a data
    /// file's path and record count, its partition a named record used
    /// again by name.
    pub(crate) fn manifest_schema() -> Value {
        json!({ "type": "record", "name": "manifest_entry", "fields": [
            { "name": "status", "type": "int" },
            { "name": "snapshot_id", "type": ["null", "long"] },
            { "name": "data_file", "type": { "type": "record", "name": "r2", "fields": [
                { "name": "content", "type": "int" },
                { "name": "file_path", "type": "string" },
                { "name": "file_format", "type": "string" },
                { "name": "partition", "type": { "type": "record", "name": "r102", "fields": [
                    { "name": "id_bucket", "type": ["null", { "type": "int", "logicalType": "x" }] }
                ]}},
                { "name": "previous", "type": ["null", "r102"] },
                { "name": "record_count", "type": "long" },
                { "name": "column_sizes", "type": ["null", { "type": "array", "items": {
                    "type": "record", "name": "k117_v118", "fields": [
                        { "name": "key", "type": "int" }, { "name": "value", "type": "long" }
                    ]}, "logicalType": "map" }] },
                { "name": "lower_bounds", "type": ["null", { "type": "map", "values": "bytes" }] },
                { "name": "key_metadata", "type": ["null", "bytes"] },
                { "name": "sort", "type": { "type": "fixed", "name": "f", "size": 2 } },
                { "name": "kind", "type": { "type": "enum", "name": "k", "symbols": ["A", "B"] } },
                { "name": "ratio", "type": "double" },
            ]}},
        ]})
    }

    pub(crate) fn manifest_entry(path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        long(&mut out, 1); // status
        long(&mut out, 1); // snapshot_id: the long branch
        long(&mut out, 42);
        long(&mut out, 0); // content
        string(&mut out, path);
        string(&mut out, "PARQUET");
        long(&mut out, 1); // partition's id_bucket: an int
        long(&mut out, 3);
        long(&mut out, 0); // previous: null
        long(&mut out, 100); // record_count
        long(&mut out, 1); // column_sizes: an array of one block of 2
        long(&mut out, -2);
        long(&mut out, 4);
        long(&mut out, 1);
        long(&mut out, 10);
        long(&mut out, 2);
        long(&mut out, 20);
        long(&mut out, 0);
        long(&mut out, 1); // lower_bounds: a map of one
        long(&mut out, 1);
        string(&mut out, "1");
        long(&mut out, 2);
        out.extend_from_slice(&[0, 1]);
        long(&mut out, 0);
        long(&mut out, 0); // key_metadata: null
        out.extend_from_slice(&[9, 9]); // sort
        long(&mut out, 1); // kind: B
        out.extend_from_slice(&1.5f64.to_le_bytes());
        out
    }

    #[test]
    fn reads_manifests_in_every_codec() {
        for codec in ["null", "deflate", "snappy"] {
            let mut block = manifest_entry("s3://t/data/a.parquet");
            block.extend(manifest_entry("s3://t/data/b.parquet"));
            let file = file(
                &manifest_schema(),
                codec,
                &[(2, block), (1, manifest_entry("s3://t/data/c.parquet"))],
            );
            let records = records(&file).unwrap();
            let paths: Vec<&str> = records
                .iter()
                .map(|r| r["data_file"]["file_path"].as_str().unwrap())
                .collect();
            assert_eq!(
                paths,
                [
                    "s3://t/data/a.parquet",
                    "s3://t/data/b.parquet",
                    "s3://t/data/c.parquet"
                ],
                "{codec}"
            );
            assert_eq!(records[0]["snapshot_id"], 42);
            assert_eq!(records[0]["data_file"]["partition"]["id_bucket"], 3);
            assert_eq!(records[0]["data_file"]["column_sizes"][1]["value"], 20);
            assert_eq!(records[0]["data_file"]["kind"], "B");
            assert_eq!(records[0]["data_file"]["ratio"], 1.5);
        }
    }

    #[test]
    fn refuses_what_it_cant_read() {
        assert!(records(b"PAR1").is_err());
        let mut f = file(&manifest_schema(), "null", &[(1, manifest_entry("x"))]);
        f.truncate(f.len() - 20);
        assert!(records(&f).is_err());
        let f = file(&manifest_schema(), "zstandard", &[(1, manifest_entry("x"))]);
        assert!(records(&f).unwrap_err().contains("zstandard"));
    }
}
