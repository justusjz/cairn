//! Directory buckets: S3 Express One Zone's buckets, named
//! `<base>--<zone>--x-s3`, which S3 tells apart from general purpose ones by
//! that suffix alone (no general purpose bucket may have it), as SDKs do.
//!
//! Their objects are stored as any other's; what differs is how they're
//! used:
//!
//! - **Sessions.** A client asks `CreateSession` (`GET /<bucket>?session`)
//!   for credentials for one bucket, in a mode (`ReadWrite` or `ReadOnly`),
//!   which `s3express:CreateSession` on the bucket (its ARN,
//!   `arn:aws:s3express:<region>:<account>:bucket/<bucket>`) must allow, by
//!   an identity policy or the bucket's. Its token (`sessions`, with
//!   `Session::directory`) says who made it, for which bucket, in which
//!   mode; signed with it (`x-amz-s3session-token`), the bucket's zonal
//!   operations are authorized by the session alone, so that they need
//!   neither the principal's policies nor the bucket's: no look at the
//!   database before the operation's own. A session lasts five minutes, as
//!   S3's do, and is good for its bucket until then, as S3's are.
//! - **Zonal operations** (on objects, listings, HeadBucket, CreateSession)
//!   need `s3express:CreateSession` (in `ReadWrite` mode for writes), with
//!   or without a session: a request signed with other credentials is
//!   checked as a session's creation would be.
//! - **Regional operations** (creating and deleting the bucket, its policy,
//!   default encryption and lifecycle) need their own `s3express:` actions
//!   (`s3express:CreateBucket`, `s3express:PutBucketPolicy`, …), which only
//!   identity policies grant, never the bucket's own policy.
//! - **Fewer features.** No versioning, Object Lock, tags, ACLs, SSE-C,
//!   CORS, websites, ABAC or website redirects: the operations are 501,
//!   and so are the headers that would ask for them. Listings
//!   (ListObjectsV2 only) take `/` as their only delimiter, and only
//!   prefixes ending in it; a multipart upload's parts must be numbered
//!   from 1, without gaps. Every object's storage class is
//!   `EXPRESS_ONEZONE`.
//!
//! SDKs pointed at an endpoint of their own (Cairn's) address directory
//! buckets virtual-hosted (path-style for an IP address), signed for the
//! `s3express` service, and use sessions for regional operations too, and
//! even create one before CreateBucket. So a session can be made for a
//! bucket that doesn't exist yet: it's marked as such, and its requests are
//! authorized as if it were none (by its principal's policies, looked up).
//!
//! Where S3's answers weren't known (and couldn't be probed), the errors are
//! S3's for the nearest case, and noted so.

use http_body_util::Full;
use hyper::{HeaderMap, Method, Response, StatusCode, body::Bytes};

use crate::{
    App,
    auth::{Rejection, Signed},
    db::Cached,
    s3::{
        access::Access,
        actions::{Check, On, Operation},
        buckets::head::REGION,
        object_lock,
        util::{
            decode_continuation_token, encode_continuation_token, format_s3_error, header_not_implemented,
            page_size, query_param, rejection_response, timestamp_sql, unknown_credentials, xml_escape, xml_ok,
        },
    },
    sessions::{self, Directory, Session, Who},
    users::Principal,
};

/// The suffix every directory bucket's name has, and only theirs.
pub const SUFFIX: &str = "--x-s3";

/// How long a session lasts, as S3's do.
pub const SESSION_SECONDS: u64 = 300;

/// The storage class of every object of a directory bucket.
pub const STORAGE_CLASS: &str = "EXPRESS_ONEZONE";

/// The action a session's creation, and so every zonal operation, needs.
pub const CREATE_SESSION: &str = "s3express:CreateSession";

/// The condition key of a session's mode.
pub const SESSION_MODE: &str = "s3express:SessionMode";

/// The actions of S3 Express on a directory bucket or the account, which
/// policies may name.
pub const ACTIONS: &[&str] = &[
    "CreateBucket",
    "CreateSession",
    "DeleteBucket",
    "DeleteBucketPolicy",
    "GetBucketPolicy",
    "GetEncryptionConfiguration",
    "GetLifecycleConfiguration",
    "ListAllMyDirectoryBuckets",
    "PutBucketPolicy",
    "PutEncryptionConfiguration",
    "PutLifecycleConfiguration",
];

/// Whether `bucket` is a directory bucket's name.
pub fn is_directory(bucket: &str) -> bool {
    bucket.ends_with(SUFFIX)
}

/// The zone (its ID, `use1-az4`, say) a directory bucket's name names.
pub fn zone(bucket: &str) -> Option<&str> {
    let (_, zone) = bucket.strip_suffix(SUFFIX)?.rsplit_once("--")?;
    Some(zone)
}

/// Whether `name` is a valid directory bucket's: `<base>--<zone>--x-s3`, 3
/// to 63 characters in all, of lowercase letters, digits and hyphens (no
/// dots), the base starting and ending with a letter or digit, and the zone
/// an ID such as `use1-az4` (hyphen-separated parts of letters and digits,
/// starting with a letter, the last `az` and a number).
pub fn valid_name(name: &str) -> bool {
    let Some(rest) = name.strip_suffix(SUFFIX) else { return false };
    let Some((base, zone)) = rest.rsplit_once("--") else { return false };
    let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    let edges = |s: &str| s.starts_with(alphanumeric) && s.ends_with(alphanumeric);
    (3..=63).contains(&name.len())
        && name.chars().all(|c| alphanumeric(c) || c == '-')
        && edges(base)
        && !base.starts_with("xn--")
        && !base.starts_with("sthree-")
        && zone.starts_with(|c: char| c.is_ascii_lowercase())
        && zone.split('-').count() >= 2
        && zone.split('-').all(|part| !part.is_empty())
        && zone.rsplit('-').next().and_then(|az| az.strip_prefix("az")).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A directory bucket's ARN, in `account`. Every bucket is in `REGION`.
pub fn arn(account: &str, bucket: &str) -> String {
    format!("arn:aws:s3express:{REGION}:{account}:bucket/{bucket}")
}

/// What a request to a directory bucket is, by its operation (S3's name for
/// it, as `actions::operation` gives it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A zonal operation that reads.
    Reads,
    /// A zonal operation that writes.
    Writes,
    /// A regional operation, and its action.
    Regional(&'static str),
    /// One a directory bucket doesn't have.
    Unsupported,
}

impl Kind {
    pub fn of(operation: &str) -> Kind {
        match operation {
            "HeadBucket" | "ListObjectsV2" | "ListMultipartUploads" | "GetObject" | "HeadObject"
            | "GetObjectAttributes" | "ListParts" => Kind::Reads,
            "DeleteObjects" | "PutObject" | "CopyObject" | "UploadPart" | "UploadPartCopy"
            | "CreateMultipartUpload" | "CompleteMultipartUpload" | "AbortMultipartUpload" | "DeleteObject" => {
                Kind::Writes
            }
            "CreateBucket" => Kind::Regional("s3express:CreateBucket"),
            "DeleteBucket" => Kind::Regional("s3express:DeleteBucket"),
            "GetBucketPolicy" => Kind::Regional("s3express:GetBucketPolicy"),
            "PutBucketPolicy" => Kind::Regional("s3express:PutBucketPolicy"),
            "DeleteBucketPolicy" => Kind::Regional("s3express:DeleteBucketPolicy"),
            "GetBucketEncryption" => Kind::Regional("s3express:GetEncryptionConfiguration"),
            "PutBucketEncryption" | "DeleteBucketEncryption" => Kind::Regional("s3express:PutEncryptionConfiguration"),
            "GetBucketLifecycleConfiguration" => Kind::Regional("s3express:GetLifecycleConfiguration"),
            "PutBucketLifecycleConfiguration" | "DeleteBucketLifecycle" => {
                Kind::Regional("s3express:PutLifecycleConfiguration")
            }
            _ => Kind::Unsupported,
        }
    }

    /// Whether it's a zonal operation (which a session may make).
    pub fn zonal(self) -> bool {
        matches!(self, Kind::Reads | Kind::Writes)
    }
}

/// S3's refusal of what a directory bucket doesn't have, `what` (an
/// operation, a header): a 501, which S3 answers a directory bucket's
/// unsupported header with (seen: "This bucket does not support Content Md5
/// header."), as a limit of the bucket's, not something S3 lacks.
pub fn unsupported(what: &str) -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", &format!("This bucket does not support {what}."))
}

/// `unsupported`, of header `header`.
fn unsupported_header(header: &str) -> Response<Full<Bytes>> {
    unsupported(&format!("{header} header"))
}

/// The operation `operation` of a request to directory bucket `bucket` of
/// `account`, as policies see it: its checks made S3 Express's (see the
/// module's comment). Or why it's refused: a 501 for what a directory
/// bucket doesn't have, a 400 for what it doesn't take.
pub fn prepare(
    operation: &mut Operation,
    bucket: &str,
    account: &str,
    query: &str,
    headers: &HeaderMap,
) -> Result<Kind, Response<Full<Bytes>>> {
    let kind = Kind::of(operation.name);
    if kind == Kind::Unsupported {
        return Err(unsupported(operation.name));
    }
    // Zonal operations take no MD5 (seen).
    if kind.zonal() && headers.contains_key("content-md5") {
        return Err(unsupported_header("Content Md5"));
    }
    // What objects can't have here, which writes would give them.
    for name in [
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-copy-source-server-side-encryption-customer-algorithm",
        object_lock::MODE,
        object_lock::RETAIN_UNTIL,
        object_lock::LEGAL_HOLD,
        "x-amz-website-redirect-location",
        "x-amz-acl",
        "x-amz-bucket-object-lock-enabled",
    ] {
        if headers.contains_key(name) {
            return Err(unsupported_header(name));
        }
    }
    // Appends, which directory buckets have and Cairn doesn't yet (see
    // `S3-COMPATIBILITY.md`): Cairn's 501 for a header it doesn't implement.
    if headers.contains_key("x-amz-write-offset-bytes") {
        return Err(header_not_implemented("x-amz-write-offset-bytes", None));
    }
    if let Some(name) = headers.keys().find(|name| name.as_str().starts_with("x-amz-grant-")) {
        return Err(unsupported_header(name.as_str()));
    }
    if headers.get("x-amz-tagging").is_some_and(|v| !v.is_empty()) {
        return Err(unsupported_header("x-amz-tagging"));
    }
    if let Some(class) = headers.get("x-amz-storage-class")
        && class.as_bytes() != STORAGE_CLASS.as_bytes()
    {
        return Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidStorageClass",
            "The storage class you specified is not valid",
        ));
    }
    if operation.name == "ListObjectsV2"
        && let Some(refused) = refuse_listing(query)
    {
        return Err(refused);
    }
    let on = || On::Directory(account.to_owned(), bucket.to_owned());
    operation.checks = match kind {
        Kind::Regional(action) => vec![Check { action, on: on() }],
        _ => {
            // A copy's source is read as its bucket has it read.
            let source = operation.checks.iter().filter(|c| c.on.bucket() != Some(bucket)).cloned();
            let mut checks = vec![Check { action: CREATE_SESSION, on: on() }];
            checks.extend(source.map(|c| source_check(c, account)));
            checks
        }
    };
    Ok(kind)
}

/// `check`, a copy's of its source, as a directory bucket's source is read:
/// by a session's creation on it (see `prepare`). Others as they are.
pub fn source_check(check: Check, account: &str) -> Check {
    match &check.on {
        On::Object(bucket, _) if is_directory(bucket) => {
            Check { action: CREATE_SESSION, on: On::Directory(account.to_owned(), bucket.clone()) }
        }
        _ => check,
    }
}

/// A ListObjectsV2 of a directory bucket refused, if it is: only `/` is a
/// delimiter, and only a prefix ending in it is taken; nor is `start-after`
/// (S3's documented limits; their errors weren't probed).
fn refuse_listing(query: &str) -> Option<Response<Full<Bytes>>> {
    let invalid = |name: &str, value: &str, message: &str| {
        let mut rejection = Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", message);
        rejection.details.push(("ArgumentName", name.to_owned()));
        rejection.details.push(("ArgumentValue", value.to_owned()));
        Some(rejection_response(&rejection))
    };
    if let Some(delimiter) = query_param(query, "delimiter").filter(|d| !d.is_empty() && d != "/") {
        return invalid("delimiter", &delimiter, "For directory buckets, / is the only supported delimiter.");
    }
    if let Some(prefix) = query_param(query, "prefix").filter(|p| !p.is_empty() && !p.ends_with('/')) {
        return invalid("prefix", &prefix, "For directory buckets, only prefixes that end in a delimiter (/) are supported.");
    }
    if let Some(after) = query_param(query, "start-after") {
        return invalid("start-after", &after, "StartAfter is not supported for directory buckets.");
    }
    None
}

/// A CompleteMultipartUpload's parts refused, if they aren't numbered 1, 2,
/// 3, … without gaps, as a directory bucket's must be (S3's documented
/// limit; its error wasn't probed: S3's for a part list it won't take). A
/// body that isn't a part list is left to the upload's completion to
/// refuse.
pub fn refuse_parts(body: &[u8]) -> Option<Response<Full<Bytes>>> {
    let text = std::str::from_utf8(body).ok()?;
    let doc = roxmltree::Document::parse(text).ok()?;
    let numbers = doc
        .root_element()
        .children()
        .filter(|n| n.has_tag_name("Part"))
        .map(|part| part.children().find(|n| n.has_tag_name("PartNumber")).and_then(|n| n.text()).map(str::trim));
    for (expected, number) in (1u32..).zip(numbers) {
        let number = number?.parse::<u32>().ok()?;
        if number != expected {
            return Some(format_s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidPartOrder",
                "For directory buckets, part numbers must be consecutive, starting at 1.",
            ));
        }
    }
    None
}

/// What a CreateBucket of a directory bucket asks for, refused if it isn't
/// that: its `<CreateBucketConfiguration>` must say so, a single
/// Availability Zone's bucket in the zone its name names (Cairn has no
/// Local Zones). Its errors weren't probed: S3's for a configuration it
/// won't take.
pub fn refuse_configuration(bucket: &str, body: &[u8]) -> Option<Response<Full<Bytes>>> {
    let invalid = |message: &str| Some(format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message));
    let malformed = || {
        Some(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema",
        ))
    };
    if body.iter().all(u8::is_ascii_whitespace) {
        return invalid("A directory bucket's CreateBucketConfiguration must name its Location and Bucket.");
    }
    let Ok(text) = std::str::from_utf8(body) else { return malformed() };
    let Ok(doc) = roxmltree::Document::parse(text) else { return malformed() };
    let root = doc.root_element();
    if !root.has_tag_name("CreateBucketConfiguration") {
        return malformed();
    }
    let field = |parent: &str, name: &str| {
        let parent = root.children().find(|n| n.has_tag_name(parent))?;
        Some(parent.children().find(|n| n.has_tag_name(name))?.text().unwrap_or("").trim().to_owned())
    };
    if root.children().any(|n| n.has_tag_name("Tags") && n.children().any(|t| t.is_element())) {
        return Some(format_s3_error(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "Cairn doesn't implement directory buckets' tags yet.",
        ));
    }
    if root.children().any(|n| n.has_tag_name("LocationConstraint")) {
        return invalid("A directory bucket's CreateBucketConfiguration takes no LocationConstraint.");
    }
    match (field("Location", "Type").as_deref(), field("Location", "Name")) {
        (Some("AvailabilityZone"), Some(name)) if Some(name.as_str()) == zone(bucket) => {}
        (Some("AvailabilityZone"), Some(_)) => {
            return invalid("The Location's Name must be the zone the bucket's name has.");
        }
        (Some("LocalZone"), _) => return invalid("Local Zones are not supported."),
        _ => return invalid("A directory bucket's CreateBucketConfiguration must name its Location (Type and Name)."),
    }
    match (field("Bucket", "Type").as_deref(), field("Bucket", "DataRedundancy").as_deref()) {
        (Some("Directory"), Some("SingleAvailabilityZone") | None) => None,
        (Some("Directory"), Some(_)) => invalid("A directory bucket's DataRedundancy must be SingleAvailabilityZone."),
        _ => invalid("A directory bucket's CreateBucketConfiguration must name its Bucket's Type, Directory."),
    }
}

/// A response to a request to a directory bucket, as it tells about its
/// objects: their storage class is `EXPRESS_ONEZONE` (in listings, and
/// GetObjectAttributes), not `STANDARD`. Keys are escaped in them, so no
/// key is taken for an element.
pub async fn express(response: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;
    const STANDARD: &str = "<StorageClass>STANDARD</StorageClass>";
    let is_xml = response.headers().get(hyper::header::CONTENT_TYPE).is_some_and(|t| t.as_bytes() == b"application/xml");
    if !is_xml {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = body.collect().await.map(|body| body.to_bytes());
    let Some(text) = std::str::from_utf8(&bytes).ok().filter(|text| text.contains(STANDARD)) else {
        return Response::from_parts(parts, Full::new(bytes));
    };
    let text = text.replace(STANDARD, &format!("<StorageClass>{STORAGE_CLASS}</StorageClass>"));
    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    Response::from_parts(parts, Full::new(Bytes::from(text)))
}

/// The headers S3's HeadBucket of directory bucket `bucket` (of `account`)
/// has: where it is, and its ARN.
pub fn head_headers(headers: &mut HeaderMap, bucket: &str, account: &str) {
    let mut set = |name: &'static str, value: &str| {
        if let Ok(value) = value.parse() {
            headers.insert(name, value);
        }
    };
    set("x-amz-bucket-location-type", "AvailabilityZone");
    set("x-amz-bucket-location-name", zone(bucket).unwrap_or(""));
    set("x-amz-bucket-arn", &arn(account, bucket));
}

/// A DeleteBucket of directory bucket `bucket` refused while it has
/// multipart uploads in progress, as S3 refuses it (its error wasn't
/// probed: S3's for a bucket that isn't empty). A general purpose bucket's
/// are aborted.
pub async fn refuse_delete(app: &App, bucket: &str) -> anyhow::Result<Option<Response<Full<Bytes>>>> {
    let uploads = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT 1 FROM multipart_uploads WHERE bucket = $1 LIMIT 1", &[&bucket])
        .await?;
    Ok(uploads.map(|_| {
        format_s3_error(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "The bucket you tried to delete has multipart uploads in progress",
        )
    }))
}

/// The mode a CreateSession asks for (`x-amz-create-session-mode`): read
/// only, or (the default) read and write. `Err` refuses another.
fn mode(headers: &HeaderMap) -> Result<bool, Response<Full<Bytes>>> {
    match headers.get("x-amz-create-session-mode").map(|v| v.as_bytes()) {
        None | Some(b"ReadWrite") => Ok(false),
        Some(b"ReadOnly") => Ok(true),
        Some(_) => {
            let mut rejection = Rejection::new(StatusCode::BAD_REQUEST, "InvalidArgument", "Invalid session mode");
            rejection.details.push(("ArgumentName", "x-amz-create-session-mode".to_owned()));
            Err(rejection_response(&rejection))
        }
    }
}

/// CreateSession: `GET /<bucket>?session`, by `principal` (with long-term
/// or STS credentials, not a session's), whose `access` it is: a session of
/// directory bucket `bucket` (of `account`), for five minutes (or until its
/// own credentials' expiry, if sooner), in the mode it asks for, if
/// `s3express:CreateSession` on the bucket is allowed in that mode
/// (`s3express:SessionMode`). Of a bucket that isn't there, one whose
/// requests are authorized as if it were none (see the module's comment).
/// It answers the bucket's default encryption, as S3 does.
pub async fn create_session(
    app: &App,
    principal: Option<&Principal>,
    access: &mut Access,
    bucket: &str,
    account: &str,
    headers: &HeaderMap,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let denied = || format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "Access Denied");
    let Some(principal) = principal else { return Ok(denied()) };
    // Not with a session's own credentials.
    let parent = principal.session.as_ref().map(|of| &of.session);
    if parent.is_some_and(|session| session.directory.is_some()) {
        return Ok(denied());
    }
    let read_only = match mode(headers) {
        Ok(read_only) => read_only,
        Err(refused) => return Ok(refused),
    };
    if !valid_name(bucket) {
        return Ok(format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "The specified bucket does not exist"));
    }
    let exists = access.load(app, bucket).await?;
    access.context.set(SESSION_MODE, if read_only { "ReadOnly" } else { "ReadWrite" });
    let check = Check { action: CREATE_SESSION, on: On::Directory(account.to_owned(), bucket.to_owned()) };
    if exists {
        let verdict = access.verdict(&check);
        if verdict != crate::policy::Verdict::Allow {
            return Ok(access.denied(&check, verdict));
        }
    }
    // The root user's key is for getting back in, not for S3 Express.
    if principal.root {
        return Ok(format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "The root user can't create a directory bucket's session"));
    }
    let now = sessions::now();
    let mut session = match parent {
        // A role's (or another STS) session's: as it is, but its own key,
        // and no longer than it.
        Some(parent) => Session {
            key_id: sessions::new_key_id()?,
            issued: now,
            expires: parent.expires.min(now + SESSION_SECONDS),
            ..parent.clone()
        },
        None => Session {
            key_id: sessions::new_key_id()?,
            secret: String::new(),
            issued: now,
            expires: now + SESSION_SECONDS,
            who: Who::User { id: principal.id },
            policy: None,
            policy_arns: Vec::new(),
            tags: Vec::new(),
            transitive: Vec::new(),
            source_identity: None,
            chained: false,
            provider: None,
            directory: None,
        },
    };
    session.directory = Some(Directory {
        bucket: bucket.to_owned(),
        read_only,
        unauthorized: !exists,
        account: principal.account.clone(),
        path: principal.path.clone(),
        name: principal.name.clone(),
    });
    let client = app.pool.get().await?;
    let token = app.sessions.seal(&client, &mut session).await?;
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <CreateSessionResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Credentials>\
         <SessionToken>{}</SessionToken><SecretAccessKey>{}</SecretAccessKey><AccessKeyId>{}</AccessKeyId>\
         <Expiration>{}</Expiration></Credentials></CreateSessionResult>",
        xml_escape(&token),
        xml_escape(&session.secret),
        session.key_id,
        sessions::iso(session.expires),
    );
    let mut response = xml_ok(body);
    // The bucket's default encryption, which its new objects get.
    let row = client
        .query_opt_cached("SELECT sse_algorithm, sse_kms_key_id, sse_bucket_key FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    if let Some(row) = row
        && let Some(algorithm) = row.get::<_, Option<String>>(0)
    {
        let headers = response.headers_mut();
        if let Ok(value) = algorithm.parse() {
            headers.insert("x-amz-server-side-encryption", value);
        }
        if let Some(Ok(value)) = row.get::<_, Option<String>>(1).map(|key| key.parse()) {
            headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
        }
        if row.get::<_, bool>(2) {
            headers.insert("x-amz-server-side-encryption-bucket-key-enabled", hyper::header::HeaderValue::from_static("true"));
        }
    }
    Ok(response)
}

/// The most directory buckets a page of ListDirectoryBuckets lists, as in
/// S3.
const MAX_DIRECTORY_BUCKETS: i64 = 1000;

/// ListDirectoryBuckets: `GET /`, signed for `s3express`, for a principal
/// allowed `s3express:ListAllMyDirectoryBuckets`: the directory buckets of
/// its account, by name, paginated by `max-directory-buckets` and an opaque
/// `continuation-token`.
pub async fn list_directory_buckets(app: &App, account: &str, query: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    let invalid = |message: &str| format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message);
    let max = match page_size(query, "max-directory-buckets", MAX_DIRECTORY_BUCKETS, MAX_DIRECTORY_BUCKETS) {
        Ok(0) => MAX_DIRECTORY_BUCKETS,
        Ok(n) => n,
        Err(refused) => return Ok(refused),
    };
    let after = match query_param(query, "continuation-token") {
        None => String::new(),
        Some(token) => match decode_continuation_token(&token) {
            Some(name) => name,
            None => return Ok(invalid("The continuation token provided is incorrect")),
        },
    };
    let client = app.pool.get().await?;
    let rows = client
        .query_cached(
            &format!(
                "SELECT name, {} FROM buckets
                 WHERE account_id = $1 AND name LIKE '%--x-s3' AND name > $2 ORDER BY name LIMIT $3",
                timestamp_sql("created_at")
            ),
            &[&account, &after, &(max + 1)],
        )
        .await?;
    let more = rows.len() as i64 > max;
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListAllMyDirectoryBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets>",
    );
    let mut last = None;
    for row in rows.iter().take(max as usize) {
        let name: String = row.get(0);
        let created: String = row.get(1);
        body.push_str(&format!(
            "<Bucket><Name>{}</Name><CreationDate>{created}</CreationDate><BucketRegion>{REGION}</BucketRegion>\
             <BucketArn>{}</BucketArn></Bucket>",
            xml_escape(&name),
            xml_escape(&arn(account, &name)),
        ));
        last = Some(name);
    }
    body.push_str("</Buckets>");
    if let Some(last) = last.filter(|_| more) {
        body.push_str(&format!("<ContinuationToken>{}</ContinuationToken>", encode_continuation_token(&last)));
    }
    body.push_str("</ListAllMyDirectoryBucketsResult>");
    Ok(xml_ok(body))
}

/// The principal whose directory bucket's session `token` is, signed with
/// `signed` for bucket `bucket` (the request's), as its token says (see
/// `users::Principal::of_directory_session`): no look at the database. Or
/// the response refusing it: a token that isn't a session's, or one for
/// another bucket.
pub async fn authenticate(
    keys: &sessions::Keys,
    client: &deadpool_postgres::Object,
    signed: &Signed,
    token: &str,
    bucket: &str,
) -> anyhow::Result<Result<Principal, Response<Full<Bytes>>>> {
    use crate::users::Unknown;
    if signed.token.is_some() {
        return Ok(Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Only one of x-amz-security-token and x-amz-s3session-token may be specified",
        )));
    }
    let session = match keys.open(client, token).await? {
        Ok(session) => session,
        Err(sessions::Bad::Malformed) => return Ok(Err(unknown_credentials(Unknown::Token))),
        Err(sessions::Bad::Expired) => return Ok(Err(unknown_credentials(Unknown::Expired))),
    };
    if session.key_id != signed.access_key {
        return Ok(Err(unknown_credentials(Unknown::Key)));
    }
    let Some(directory) = &session.directory else { return Ok(Err(unknown_credentials(Unknown::Token))) };
    if directory.bucket != bucket {
        return Ok(Err(format_s3_error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "The session token is for another bucket",
        )));
    }
    Ok(Principal::of_directory_session(session).ok_or_else(|| unknown_credentials(Unknown::Token)))
}

/// A refusal of a write in a `ReadOnly` session.
pub fn read_only() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::FORBIDDEN, "AccessDenied", "The session is ReadOnly: it may not write")
}

/// A response to operation `operation` (S3's name for it) of directory
/// bucket `bucket` of `account`, as S3's tells about the bucket and its
/// objects (see `express`, `head_headers`); `x-amz-storage-class` on an
/// object's.
pub async fn finish(response: Response<Full<Bytes>>, operation: &str, bucket: &str, account: &str) -> Response<Full<Bytes>> {
    let mut response = express(response).await;
    if response.status().is_success() {
        match operation {
            "HeadBucket" => head_headers(response.headers_mut(), bucket, account),
            "HeadObject" | "GetObject" => storage_class(response.headers_mut()),
            _ => {}
        }
    }
    response
}

/// Tells an object's storage class, `EXPRESS_ONEZONE`, in `headers` (a
/// read's).
pub fn storage_class(headers: &mut HeaderMap) {
    headers.insert("x-amz-storage-class", hyper::header::HeaderValue::from_static(STORAGE_CLASS));
}

/// Whether a request to `method` on `path` (a route's) may be signed for
/// `s3express`: one to a directory bucket, or ListDirectoryBuckets (`GET
/// /`).
pub fn takes_express(method: &Method, path: &str) -> bool {
    let path = path.trim_start_matches('/');
    let bucket = path.split_once('/').map_or(path, |(bucket, _)| bucket);
    (bucket.is_empty() && method == Method::GET) || is_directory(bucket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for name in ["data--use1-az4--x-s3", "a1b--usw2-az1--x-s3", "my-logs--use1-lax1-az1--x-s3", "a--b--usw2-az1--x-s3"] {
            assert!(valid_name(name), "{name}");
            assert!(is_directory(name), "{name}");
        }
        assert_eq!(zone("data--use1-az4--x-s3"), Some("use1-az4"));
        assert_eq!(zone("a--b--usw2-az1--x-s3"), Some("usw2-az1"));
        for name in [
            "data--x-s3",
            "--use1-az4--x-s3",
            "data.logs--use1-az4--x-s3",
            "Data--use1-az4--x-s3",
            "data---use1-az4--x-s3",
            "data--1use-az4--x-s3",
            "data--use1--az4--x-s3",
            "data--use1-az4-",
            "xn--data--use1-az4--x-s3",
            &format!("{}--use1-az4--x-s3", "a".repeat(48)),
        ] {
            assert!(!valid_name(name), "{name}");
        }
        assert!(!is_directory("data"));
        assert!(takes_express(&Method::GET, "/"));
        assert!(!takes_express(&Method::PUT, "/"));
        assert!(takes_express(&Method::PUT, "/data--use1-az4--x-s3/a/b"));
        assert!(!takes_express(&Method::PUT, "/data/a"));
    }

    #[test]
    fn kinds() {
        assert_eq!(Kind::of("GetObject"), Kind::Reads);
        assert_eq!(Kind::of("CopyObject"), Kind::Writes);
        assert_eq!(Kind::of("DeleteBucketEncryption"), Kind::Regional("s3express:PutEncryptionConfiguration"));
        for unsupported in ["ListObjects", "ListObjectVersions", "PutBucketVersioning", "GetObjectTagging", "PutBucketCors"] {
            assert_eq!(Kind::of(unsupported), Kind::Unsupported, "{unsupported}");
        }
    }

    #[test]
    fn listings() {
        assert!(refuse_listing("list-type=2").is_none());
        assert!(refuse_listing("list-type=2&delimiter=%2F&prefix=a%2Fb%2F").is_none());
        assert!(refuse_listing("list-type=2&delimiter=").is_none());
        assert!(refuse_listing("list-type=2&delimiter=-").is_some());
        assert!(refuse_listing("list-type=2&prefix=a").is_some());
        assert!(refuse_listing("list-type=2&start-after=a").is_some());
    }

    #[test]
    fn parts() {
        let body = |numbers: &[u32]| {
            let parts: String =
                numbers.iter().map(|n| format!("<Part><ETag>\"x\"</ETag><PartNumber>{n}</PartNumber></Part>")).collect();
            format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>")
        };
        assert!(refuse_parts(body(&[1, 2, 3]).as_bytes()).is_none());
        assert!(refuse_parts(body(&[1]).as_bytes()).is_none());
        assert!(refuse_parts(body(&[1, 3]).as_bytes()).is_some());
        assert!(refuse_parts(body(&[2]).as_bytes()).is_some());
        assert!(refuse_parts(body(&[2, 1]).as_bytes()).is_some());
        // Left to the completion to refuse.
        assert!(refuse_parts(b"<CompleteMultipartUpload>").is_none());
    }

    #[test]
    fn configurations() {
        let bucket = "data--use1-az4--x-s3";
        let configuration = |location: &str, kind: &str| {
            format!(
                "<CreateBucketConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{location}{kind}\
                 </CreateBucketConfiguration>"
            )
        };
        let location = |kind: &str, name: &str| format!("<Location><Type>{kind}</Type><Name>{name}</Name></Location>");
        let directory = "<Bucket><DataRedundancy>SingleAvailabilityZone</DataRedundancy><Type>Directory</Type></Bucket>";
        let refused = |body: String| refuse_configuration(bucket, body.as_bytes()).map(|r| r.status());
        assert_eq!(refused(configuration(&location("AvailabilityZone", "use1-az4"), directory)), None);
        assert_eq!(refused(configuration(&location("AvailabilityZone", "use1-az5"), directory)), Some(StatusCode::BAD_REQUEST));
        assert_eq!(refused(configuration(&location("LocalZone", "use1-az4"), directory)), Some(StatusCode::BAD_REQUEST));
        assert_eq!(refused(configuration(&location("AvailabilityZone", "use1-az4"), "")), Some(StatusCode::BAD_REQUEST));
        assert_eq!(refused(configuration("", directory)), Some(StatusCode::BAD_REQUEST));
        assert_eq!(refused(String::new()), Some(StatusCode::BAD_REQUEST));
        assert_eq!(refused("<CreateBucketConfiguration>".to_owned()), Some(StatusCode::BAD_REQUEST));
    }

    #[tokio::test]
    async fn storage_classes() {
        use http_body_util::BodyExt;
        let listing = xml_ok("<Contents><Key>&lt;StorageClass&gt;</Key><StorageClass>STANDARD</StorageClass></Contents>".to_owned());
        let body = express(listing).await.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"<Contents><Key>&lt;StorageClass&gt;</Key><StorageClass>EXPRESS_ONEZONE</StorageClass></Contents>");
    }
}
