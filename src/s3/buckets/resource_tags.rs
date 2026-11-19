//! S3 Control's TagResource, UntagResource and ListTagsForResource
//! (`/v20180820/tags/{resourceArn}`), on a bucket: the same tag set as
//! GetBucketTagging's (see `tagging`), and with the bucket's ABAC enabled,
//! the only way to change it, as in S3. As S3 has them (probed, see
//! `plans/abac.md`):
//!
//! - TagResource adds tags, or changes their values; it carries the tags as
//!   `aws:RequestTag/…`, and their keys as `aws:TagKeys`. UntagResource
//!   removes keys (`?tagKeys=`, which needn't be there), which it carries as
//!   `aws:TagKeys`. Both answer 204, ABAC or not.
//! - Neither takes none: InvalidTag "At least one tag is required." An `aws:`
//!   key is InvalidTag, and more than 50 tags (with the bucket's) is
//!   TooManyTags.
//! - ListTagsForResource lists an untagged bucket's as none (not
//!   GetBucketTagging's NoSuchTagSet).
//! - A bucket that doesn't exist is NoSuchResource; an ARN that isn't a
//!   bucket's (an object's, say) is InvalidURI.
//!
//! Like S3 Control's other requests here (see `public_access`), only the
//! signer's own account's: it names it in `x-amz-account-id`. Access Grants'
//! instances, locations and grants are tagged here too (see
//! `access_grants::tag_resource`).

use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, body::Bytes};
use percent_encoding::percent_decode_str;

use crate::db::Cached;
use crate::{
    App,
    s3::{
        access::Access,
        actions::{Check, On},
        tags::{self, Tags},
        util::{format_s3_error, rejection_response, xml_escape, xml_ok},
    },
    users::Principal,
};

/// S3 Control's path for a resource's tags: the resource's ARN follows.
const PREFIX: &str = "/v20180820/tags/";

const CONTROL_XMLNS: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

/// The most times a change is tried again for another's that came first.
const ATTEMPTS: usize = 10;

/// Whether a request to `path` (as sent) with `headers` is S3 Control's, on
/// a resource's tags (see `public_access::is_control`).
pub fn is_control(path: &str, headers: &hyper::HeaderMap) -> bool {
    path.starts_with(PREFIX) && headers.contains_key("x-amz-account-id")
}

/// The bucket a resource's ARN (as in the path) names, if it names one.
fn bucket_of(path: &str) -> Option<String> {
    let arn = percent_decode_str(path.strip_prefix(PREFIX)?)
        .decode_utf8()
        .ok()?;
    let bucket = arn.strip_prefix("arn:aws:s3:::")?;
    (!bucket.is_empty() && !bucket.contains('/')).then(|| bucket.to_owned())
}

/// What a request on a resource's tags is: its operation, and its action.
fn operation(method: &Method) -> Option<(&'static str, &'static str)> {
    match *method {
        Method::GET => Some(("ListTagsForResource", "s3:ListTagsForResource")),
        Method::POST => Some(("TagResource", "s3:TagResource")),
        Method::DELETE => Some(("UntagResource", "s3:UntagResource")),
        _ => None,
    }
}

fn none_given() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "InvalidTag",
        "At least one tag is required.",
    )
}

fn no_such_resource() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchResource",
        "The specified resource doesn't exist.",
    )
}

/// A change to a bucket's tags.
pub(crate) enum Change {
    Add(Tags),
    Remove(Vec<String>),
}

/// Handles a request `is_control` says is one, by `principal`, as `access`
/// decides it; `secret` is what its body is signed with.
pub async fn handle(
    app: &App,
    req: Request<crate::listen::ClientBody>,
    principal: Option<&Principal>,
    access: &mut Access,
    secret: &str,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some((_, action)) = operation(req.method()) else {
        return Ok(format_s3_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        ));
    };
    let named = req
        .headers()
        .get("x-amz-account-id")
        .and_then(|v| v.to_str().ok());
    if principal.is_none_or(|p| named != Some(p.account.as_str())) {
        return Ok(format_s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "Access Denied",
        ));
    }
    // An Access Grants resource's (see `access_grants`), or a bucket's.
    let arn = req
        .uri()
        .path()
        .strip_prefix(PREFIX)
        .and_then(|arn| percent_decode_str(arn).decode_utf8().ok())
        .map(|a| a.into_owned());
    let grants = arn
        .as_deref()
        .and_then(crate::s3::access_grants::resource_of);
    let bucket = bucket_of(req.uri().path());
    if bucket.is_none() && grants.is_none() {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidURI",
            "Couldn't parse the specified URI.",
        ));
    }
    // What it changes, which its checks may test.
    let change = match req.method().clone() {
        Method::POST => {
            let body = match crate::s3::read_body(req, secret, true).await? {
                Ok(body) => body,
                Err(rejection) => return Ok(rejection_response(&rejection)),
            };
            let tags = match parse_tag_request(&body) {
                Ok(tags) => tags,
                Err(refused) => return Ok(refused),
            };
            tags.set_context(&mut access.context, "aws:RequestTag", Some("aws:TagKeys"));
            Some(Change::Add(tags))
        }
        Method::DELETE => {
            let query = req.uri().query().unwrap_or("");
            let keys: Vec<String> = query
                .split('&')
                .filter_map(|pair| pair.split_once('=').filter(|(name, _)| *name == "tagKeys"))
                .map(|(_, value)| crate::s3::util::decode_path_param(value))
                .collect();
            if keys.is_empty() {
                return Ok(none_given());
            }
            access.context.set_all("aws:TagKeys", keys.clone());
            Some(Change::Remove(keys))
        }
        _ => None,
    };
    if let Some((owner, resource)) = grants {
        let account = principal.expect("checked above").account.clone();
        if owner != account {
            return Ok(no_such_resource());
        }
        let arn = arn.expect("it named the resource");
        return crate::s3::access_grants::tag_resource(
            app, access, &account, &arn, &resource, action, change,
        )
        .await;
    }
    let bucket = bucket.expect("checked above");
    let exists = access.load(app, &bucket).await?;
    let check = Check {
        action,
        on: On::Bucket(bucket.clone()),
    };
    if let Some((check, verdict)) = access.first_denied(std::slice::from_ref(&check)) {
        return Ok(match exists {
            true => access.denied(check, verdict),
            false => no_such_resource(),
        });
    }
    if !exists {
        return Ok(no_such_resource());
    }
    match change {
        None => list(app, &bucket).await,
        Some(change) => apply(app, &bucket, change).await,
    }
}

/// TagResource's tags, from its `<TagResourceRequest>`.
fn parse_tag_request(body: &[u8]) -> Result<Tags, Response<Full<Bytes>>> {
    let text = std::str::from_utf8(body).map_err(|_| tags::malformed("not UTF-8"))?;
    let doc = roxmltree::Document::parse(text).map_err(|e| tags::malformed(&e.to_string()))?;
    let Some(list) = doc
        .root_element()
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == "Tags")
    else {
        return Err(none_given());
    };
    let tags = Tags::from_elements(list, tags::On::Resource)?;
    if tags.is_empty() {
        return Err(none_given());
    }
    if let Some(refused) = tags.too_many() {
        return Err(refused);
    }
    Ok(tags)
}

/// The bucket's tags, as stored (`None`: none), or `None` if it's gone.
async fn stored(app: &App, bucket: &str) -> anyhow::Result<Option<Option<String>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT tags FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.map(|row| row.get(0)))
}

/// ListTagsForResource.
pub(crate) async fn list(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(stored) = stored(app, bucket).await? else {
        return Ok(no_such_resource());
    };
    let tags = Tags::from_stored(stored.as_deref().unwrap_or(""));
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListTagsForResourceResult xmlns=\"{CONTROL_XMLNS}\"><Tags>"
    );
    for (key, value) in tags.iter() {
        out.push_str(&format!(
            "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
            xml_escape(key),
            xml_escape(value)
        ));
    }
    out.push_str("</Tags></ListTagsForResourceResult>");
    Ok(xml_ok(out))
}

/// TagResource and UntagResource: the bucket's tags changed as `change`
/// says (`cairn_swap_bucket_tags`), tried again if another change came
/// first.
pub(crate) async fn apply(
    app: &App,
    bucket: &str,
    change: Change,
) -> anyhow::Result<Response<Full<Bytes>>> {
    for _ in 0..ATTEMPTS {
        let Some(old) = stored(app, bucket).await? else {
            return Ok(no_such_resource());
        };
        let current = Tags::from_stored(old.as_deref().unwrap_or(""));
        let new = match &change {
            Change::Add(tags) => current.merged(tags),
            Change::Remove(keys) => current.without(keys),
        };
        if let Some(refused) = new.too_many() {
            return Ok(refused);
        }
        let new = Some(new)
            .filter(|tags| !tags.is_empty())
            .map(|tags| tags.stored());
        let status: String = app
            .pool
            .get()
            .await?
            .query_one_cached(
                "SELECT pg_temp.cairn_swap_bucket_tags($1, $2, $3)",
                &[&bucket, &old, &new],
            )
            .await?
            .get(0);
        match status.as_str() {
            "ok" => {
                return Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            "missing" => return Ok(no_such_resource()),
            _ => continue,
        }
    }
    Err(crate::Contended(format!("the tags of bucket {bucket} kept changing")).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_buckets_by_their_arns() {
        assert_eq!(
            bucket_of("/v20180820/tags/arn%3Aaws%3As3%3A%3A%3Ab1").as_deref(),
            Some("b1")
        );
        assert_eq!(
            bucket_of("/v20180820/tags/arn:aws:s3:::b1").as_deref(),
            Some("b1")
        );
        assert_eq!(bucket_of("/v20180820/tags/arn:aws:s3:::b1/key"), None);
        assert_eq!(bucket_of("/v20180820/tags/arn:aws:s3:::"), None);
        assert_eq!(
            bucket_of("/v20180820/tags/arn:aws:iam::123456789012:user/a"),
            None
        );
    }

    #[test]
    fn parses_tag_requests() {
        let request = |tags: &str| {
            format!(
                r#"<TagResourceRequest xmlns="{CONTROL_XMLNS}"><Tags>{tags}</Tags></TagResourceRequest>"#
            )
        };
        let tag = |k: &str, v: &str| format!("<Tag><Key>{k}</Key><Value>{v}</Value></Tag>");
        let tags =
            parse_tag_request(request(&(tag("team", "red") + &tag("env", "dev"))).as_bytes())
                .unwrap();
        assert_eq!(
            tags.iter().collect::<Vec<_>>(),
            [("env", "dev"), ("team", "red")]
        );
        let status = |body: String| parse_tag_request(body.as_bytes()).unwrap_err().status();
        assert_eq!(status(request("")), StatusCode::BAD_REQUEST);
        assert_eq!(status(request(&tag("aws:x", "1"))), StatusCode::BAD_REQUEST);
        let many: String = (0..51).map(|i| tag(&format!("k{i}"), "v")).collect();
        assert_eq!(status(request(&many)), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("<TagResourceRequest><Tags>".to_owned()),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status("<TagResourceRequest/>".to_owned()),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn merges_and_removes() {
        let tags = |pairs: &[(&str, &str)]| {
            Tags::from_stored(
                &pairs
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("&"),
            )
        };
        let merged = tags(&[("a", "1"), ("c", "3")]).merged(&tags(&[("b", "2"), ("c", "4")]));
        assert_eq!(merged, tags(&[("a", "1"), ("b", "2"), ("c", "4")]));
        assert_eq!(
            merged.without(&["b".to_owned(), "x".to_owned()]),
            tags(&[("a", "1"), ("c", "4")])
        );
    }
}
