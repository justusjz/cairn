//! GetObjectAttributes (`GET /{bucket}/{key}?attributes`): what S3 tells of
//! an object version without its data, as the `x-amz-object-attributes`
//! header asks for it (probed; see `plans/probes/parts_probe.py`):
//!
//! - `ETag`, unquoted; `ObjectSize`; `StorageClass` (always STANDARD);
//! - `Checksum`: the object's, a composite one without its `-N`;
//! - `ObjectParts`, for a multipart object only: its part count, and, if its
//!   checksum is composite, its parts (numbered from 1, whatever numbers
//!   they were uploaded as), a page of them, by `x-amz-max-parts` and
//!   `x-amz-part-number-marker`.
//!
//! An SSE-C object's need its key; conditional headers are ignored.

use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes, header};

use crate::{
    App,
    auth::Rejection,
    db::Cached,
    encryption::{Field, Owner, Salt, Storing},
    s3::{
        checksums::Type,
        objects::get::{ObjectVersion, is_multipart, lookup_version},
        sse::{self, Stored},
        sse_c::CustomerKey,
        util::{format_s3_error, rejection_response, with_version_id, xml_escape, xml_ok},
    },
};

/// The attributes that can be asked for, in the order S3 tells them.
const ATTRIBUTES: [&str; 5] = ["ETag", "Checksum", "ObjectParts", "StorageClass", "ObjectSize"];

/// The header that names the attributes.
const HEADER: &str = "x-amz-object-attributes";

/// The most parts a page lists, unless `x-amz-max-parts` says otherwise.
const MAX_PARTS: i64 = 1000;

/// What a request asks for: which attributes (as flags, in `ATTRIBUTES`'
/// order), and the page of parts.
pub struct Asked {
    wanted: [bool; 5],
    max_parts: i64,
    marker: i64,
}

impl Asked {
    /// What `headers` ask for, or S3's 400 (probed). Several headers count
    /// as one list; names are case-sensitive, and trimmed.
    pub fn from_headers(headers: &HeaderMap) -> Result<Asked, Response<Full<Bytes>>> {
        let values: Vec<&str> = headers.get_all(HEADER).iter().filter_map(|v| v.to_str().ok()).collect();
        if values.is_empty() {
            return Err(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "The x-amz-object-attributes header specifying the attributes to be retrieved is either missing or empty",
            ));
        }
        let mut wanted = [false; 5];
        for name in values.iter().flat_map(|v| v.split(',')).map(str::trim) {
            match ATTRIBUTES.iter().position(|a| *a == name) {
                Some(i) => wanted[i] = true,
                None => return Err(invalid(HEADER, name, "Invalid attribute name specified.")),
            }
        }
        let number = |name: &'static str, default: i64| match headers.get(name) {
            None => Ok(default),
            Some(value) => {
                let text = value.to_str().unwrap_or("");
                text.parse::<i32>().map(i64::from).map_err(|_| {
                    invalid(name, text, &format!("Provided {name} not an integer or within integer range"))
                })
            }
        };
        Ok(Asked {
            wanted,
            max_parts: number("x-amz-max-parts", MAX_PARTS)?,
            marker: number("x-amz-part-number-marker", 0)?,
        })
    }

    fn wants(&self, attribute: &str) -> bool {
        ATTRIBUTES.iter().position(|a| *a == attribute).is_some_and(|i| self.wanted[i])
    }
}

/// S3's 400 InvalidArgument, naming the argument and its value.
fn invalid(name: &str, value: &str, message: &str) -> Response<Full<Bytes>> {
    let mut rejection = Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", message);
    rejection.details.push(("ArgumentName", name.to_owned()));
    rejection.details.push(("ArgumentValue", value.to_owned()));
    rejection_response(&rejection)
}

/// S3's 400 for `?attributes` with `?partNumber` (probed).
pub fn with_part_number() -> Response<Full<Bytes>> {
    invalid("ResourceType", "attributes", "Conflicting query string parameters: attributes, partNumber")
}

/// GetObjectAttributes.
pub async fn get_object_attributes(
    app: &App,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    asked: &Asked,
    customer_key: Option<&CustomerKey>,
    role: Option<uuid::Uuid>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let client = app.pool.get().await?;
    let ObjectVersion { id, etag, encryption, size, last_modified, version_id, checksum, .. } =
        match lookup_version(&client, bucket, key, version_id).await? {
            Ok(version) => version,
            Err(missing) => return Ok(missing.read_response()),
        };
    if let Err(refused) = sse::check(&encryption, customer_key) {
        return Ok(refused);
    }
    let etag = match sse::plain_etag(app, &encryption, &etag, bucket, key).await? {
        Ok(etag) => etag,
        Err(refused) => return Ok(refused),
    };
    let checksum = checksum.filter(|_| asked.wants("Checksum") || asked.wants("ObjectParts"));
    // Its checksums are sealed under its key, if it's encrypted.
    let object_key = match (&encryption, &checksum) {
        (Stored::Plain, _) | (_, None) => None,
        _ => match sse::open(app, &encryption, customer_key, role, bucket, key).await? {
            Ok(object_key) => object_key,
            Err(refused) => return Ok(refused),
        },
    };
    let storing = match &object_key {
        Some(object_key) => Storing::Sealed(object_key),
        None => Storing::Plain,
    };

    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if asked.wants("ETag") {
        body.push_str(&format!("<ETag>{}</ETag>", xml_escape(&etag)));
    }
    if asked.wants("Checksum")
        && let Some(checksum) = &checksum
    {
        let value = checksum.read(storing, bucket, key)?.value;
        // A composite one is told without its part count.
        let value = match checksum.kind {
            Type::Composite => value.rsplit_once('-').map_or(value.clone(), |(value, _)| value.to_owned()),
            Type::FullObject => value,
        };
        let element = checksum.algorithm.element();
        body.push_str(&format!(
            "<Checksum><{element}>{value}</{element}><ChecksumType>{}</ChecksumType></Checksum>",
            checksum.kind.name()
        ));
    }
    if asked.wants("ObjectParts") && is_multipart(&etag) {
        let rows = client
            .query_cached(
                "SELECT coalesce(plain_size, size), checksum, enc_salt FROM parts
                 WHERE object_id = $1 ORDER BY part_number",
                &[&id],
            )
            .await?;
        body.push_str(&format!("<ObjectParts><PartsCount>{}</PartsCount>", rows.len()));
        // Its parts are listed only with a composite checksum (probed).
        if let Some(checksum) = checksum.as_ref().filter(|c| c.kind == Type::Composite) {
            let (first, next, truncated) = page(rows.len() as i64, asked.marker, asked.max_parts);
            body.push_str(&format!(
                "<PartNumberMarker>{}</PartNumberMarker><NextPartNumberMarker>{next}</NextPartNumberMarker>\
                 <MaxParts>{}</MaxParts><IsTruncated>{truncated}</IsTruncated>",
                asked.marker, asked.max_parts
            ));
            let element = checksum.algorithm.element();
            let listed = match next >= first {
                true => &rows[first as usize - 1..next as usize],
                false => &[][..],
            };
            for (number, row) in (first..).zip(listed) {
                let size: i64 = row.get(0);
                let value = match row.get::<_, Option<&str>>(1) {
                    None => None,
                    Some(stored) => {
                        let salt: Option<Salt> = row
                            .get::<_, Option<Vec<u8>>>(2)
                            .map(|salt| salt.try_into().expect("a salt is 16 bytes (parts_encrypted)"));
                        Some(match (&storing, &salt) {
                            (Storing::Plain, _) => stored.to_owned(),
                            (_, Some(salt)) => storing.read(Field::Checksum, Owner::Part(salt), stored)?,
                            (_, None) => anyhow::bail!("a part of an encrypted object has no salt"),
                        })
                    }
                };
                body.push_str(&format!("<Part><PartNumber>{number}</PartNumber><Size>{size}</Size>"));
                if let Some(value) = value {
                    body.push_str(&format!("<{element}>{value}</{element}>"));
                }
                body.push_str("</Part>");
            }
        }
        body.push_str("</ObjectParts>");
    }
    if asked.wants("StorageClass") {
        body.push_str("<StorageClass>STANDARD</StorageClass>");
    }
    if asked.wants("ObjectSize") {
        body.push_str(&format!("<ObjectSize>{size}</ObjectSize>"));
    }
    body.push_str("</GetObjectAttributesResponse>");
    let mut response = xml_ok(body);
    response.headers_mut().insert(header::LAST_MODIFIED, last_modified.parse()?);
    Ok(with_version_id(response, version_id.as_deref()))
}

/// A page of `count` parts after `marker`, of at most `max`: its first
/// part's number, the `NextPartNumberMarker` (its last part's number, 0 if
/// it has none), and whether parts follow it. As S3 pages them (probed),
/// a negative `max` is a page of none that's truncated, its next marker
/// `max`.
fn page(count: i64, marker: i64, max: i64) -> (i64, i64, bool) {
    let first = marker.max(0) + 1;
    if max < 0 {
        return (first, max, true);
    }
    let last = (marker.max(0) + max).min(count);
    match last >= first {
        true => (first, last, last < count),
        false => (first, 0, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_as_s3_does() {
        // As the probe saw them, of 3 parts.
        assert_eq!(page(3, 0, 1000), (1, 3, false));
        assert_eq!(page(3, 0, 1), (1, 1, true));
        assert_eq!(page(3, 1, 1000), (2, 3, false));
        assert_eq!(page(3, 3, 1000), (4, 0, false));
        assert_eq!(page(3, 0, 0), (1, 0, false));
        assert_eq!(page(3, 0, -1), (1, -1, true));
        assert_eq!(page(3, 7, 1000), (8, 0, false));
    }

    #[test]
    fn reads_what_is_asked() {
        let asked = |values: &[&str]| {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(HEADER, value.parse().unwrap());
            }
            Asked::from_headers(&headers).map(|asked| asked.wanted).map_err(|r| r.status())
        };
        assert_eq!(asked(&["ETag, ObjectSize"]), Ok([true, false, false, false, true]));
        assert_eq!(asked(&["ETag", "ObjectSize"]), Ok([true, false, false, false, true]));
        assert_eq!(asked(&["ETag,ETag"]), Ok([true, false, false, false, false]));
        for bad in [&["etag"][..], &[""], &["ETag,Bogus"]] {
            assert_eq!(asked(bad), Err(StatusCode::BAD_REQUEST), "{bad:?}");
        }
        assert_eq!(asked(&[]), Err(StatusCode::BAD_REQUEST));
    }
}
