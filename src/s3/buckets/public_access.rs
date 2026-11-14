//! Block Public Access: a bucket's public access block
//! (GetPublicAccessBlock, PutPublicAccessBlock, DeletePublicAccessBlock,
//! `?publicAccessBlock`), and its account's (S3 Control's operations of the
//! same names, on `/v20180820/configuration/publicAccessBlock`), which count
//! together: a flag is on if either has it.
//!
//! - `BlockPublicPolicy`: a public bucket policy (`Policy::is_public`) is
//!   refused when it's set (`policy`).
//! - `RestrictPublicBuckets`: a bucket's public policy allows nothing to
//!   anyone outside the bucket's account, anonymous requests included
//!   (`access`); its own account's users keep what it allows them, as in S3.
//! - `BlockPublicAcls`, `IgnorePublicAcls`: kept and told, as S3 does; Cairn
//!   refuses every ACL but `private` anyway (`acl`), so both always hold.
//!
//! New buckets have all four, as S3's do since 2023; the buckets made before
//! there were blocks have none. New accounts have none, as AWS's.
//!
//! The account's block is set (`s3:PutAccountPublicAccessBlock`) by its
//! root and whom its policies allow. S3 Control's clients name the
//! account in the request's host too (`<account>.<endpoint>`), so they're
//! told apart by the path and the `x-amz-account-id` header (`is_control`).

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{
    App,
    db::Cached,
    s3::util::{format_s3_error, xml_ok},
};

/// A public access block's four flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Block {
    pub block_public_acls: bool,
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    pub restrict_public_buckets: bool,
}

/// The flags' elements, in S3's order, and their bits as they're stored.
const FLAGS: [(&str, i16); 4] =
    [("BlockPublicAcls", 1), ("IgnorePublicAcls", 2), ("BlockPublicPolicy", 4), ("RestrictPublicBuckets", 8)];

impl Block {
    /// As it's stored (`buckets.public_access_block`).
    pub fn from_bits(bits: i16) -> Block {
        let on = |bit| bits & bit != 0;
        Block {
            block_public_acls: on(1),
            ignore_public_acls: on(2),
            block_public_policy: on(4),
            restrict_public_buckets: on(8),
        }
    }

    pub fn bits(self) -> i16 {
        self.flags().iter().zip(FLAGS).filter(|(on, _)| **on).map(|(_, (_, bit))| bit).sum()
    }

    fn flags(self) -> [bool; 4] {
        [self.block_public_acls, self.ignore_public_acls, self.block_public_policy, self.restrict_public_buckets]
    }

    /// A `<PublicAccessBlockConfiguration>` document's, or `None` if it isn't
    /// one. A flag that isn't there is off, as in S3.
    fn parse(body: &[u8]) -> Option<Block> {
        let doc = roxmltree::Document::parse(std::str::from_utf8(body).ok()?).ok()?;
        let root = doc.root_element();
        if root.tag_name().name() != "PublicAccessBlockConfiguration" {
            return None;
        }
        let mut bits = 0;
        for element in root.children().filter(|n| n.is_element()) {
            let (_, bit) = FLAGS.iter().find(|(name, _)| *name == element.tag_name().name())?;
            match element.text().unwrap_or("").trim() {
                "true" => bits |= bit,
                "false" => {}
                _ => return None,
            }
        }
        Some(Block::from_bits(bits))
    }

    fn xml(self, xmlns: &str) -> String {
        let flags: String = self
            .flags()
            .iter()
            .zip(FLAGS)
            .map(|(on, (name, _))| format!("<{name}>{on}</{name}>"))
            .collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <PublicAccessBlockConfiguration xmlns=\"{xmlns}\">{flags}\
             </PublicAccessBlockConfiguration>"
        )
    }
}

/// A bucket's public access block: `None` if there's no such bucket,
/// `Some(None)` if it has none.
pub async fn get(app: &App, bucket: &str) -> anyhow::Result<Option<Option<Block>>> {
    let row = app
        .pool
        .get()
        .await?
        .query_opt_cached("SELECT public_access_block FROM buckets WHERE name = $1", &[&bucket])
        .await?;
    Ok(row.map(|row| row.get::<_, Option<i16>>(0).map(Block::from_bits)))
}

/// Sets (`None`: removes) a bucket's public access block (T32). Whether the
/// bucket exists.
pub async fn set(app: &App, bucket: &str, block: Option<Block>) -> anyhow::Result<bool> {
    Ok(app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_set_public_access_block($1, $2)",
            &[&bucket, &block.map(Block::bits)],
        )
        .await?
        .get(0))
}

/// An account's public access block (none, if it has none).
pub async fn account<C: deadpool_postgres::GenericClient>(client: &C, account: &str) -> anyhow::Result<Option<Block>> {
    let row = client
        .query_opt_cached("SELECT public_access_block FROM accounts WHERE id = $1", &[&account])
        .await?;
    Ok(row.and_then(|row| row.get::<_, Option<i16>>(0)).map(Block::from_bits))
}

/// Sets (`None`: removes) an account's public access block (T41). Whether
/// the account exists.
pub async fn set_account(app: &App, account: &str, block: Option<Block>) -> anyhow::Result<bool> {
    Ok(app
        .pool
        .get()
        .await?
        .query_one_cached(
            "SELECT pg_temp.cairn_set_account_public_access_block($1, $2)",
            &[&account, &block.map(Block::bits)],
        )
        .await?
        .get(0))
}

const S3_XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const CONTROL_XMLNS: &str = "http://awss3control.amazonaws.com/doc/2018-08-20/";

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

/// GetPublicAccessBlock.
pub async fn get_public_access_block(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match get(app, bucket).await? {
        None => no_such_bucket(),
        Some(None) => no_such_block(),
        Some(Some(block)) => xml_ok(block.xml(S3_XMLNS)),
    })
}

/// PutPublicAccessBlock: replaces the bucket's block with the document's.
/// 200, as in S3.
pub async fn put_public_access_block(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(block) = Block::parse(&body) else {
        return Ok(malformed());
    };
    Ok(match set(app, bucket, Some(block)).await? {
        true => Response::new(Full::new(Bytes::new())),
        false => no_such_bucket(),
    })
}

/// DeletePublicAccessBlock: 204, with a block or without.
pub async fn delete_public_access_block(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match set(app, bucket, None).await? {
        true => Response::builder().status(StatusCode::NO_CONTENT).body(Full::new(Bytes::new())).unwrap(),
        false => no_such_bucket(),
    })
}

fn no_such_block() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::NOT_FOUND,
        "NoSuchPublicAccessBlockConfiguration",
        "The public access block configuration was not found",
    )
}

fn malformed() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::BAD_REQUEST,
        "MalformedXML",
        "The XML you provided was not well-formed or did not validate against our published schema",
    )
}

/// S3 Control's path for an account's public access block.
pub const CONTROL_PATH: &str = "/v20180820/configuration/publicAccessBlock";

/// Whether a request to `path` (as sent, whatever its host) with `headers`
/// is S3 Control's, on an account's public access block: S3 Control's
/// requests name their account in `x-amz-account-id`, which S3's don't
/// send. (Without it, the path is a key `configuration/publicAccessBlock`
/// in a bucket `v20180820`.)
pub fn is_control(path: &str, headers: &hyper::HeaderMap) -> bool {
    path == CONTROL_PATH && headers.contains_key("x-amz-account-id")
}

/// What an S3 Control request on an account's block is: its operation and
/// the action it needs (deleting it is its `Put` action, as in S3).
pub fn control_operation(method: &hyper::Method) -> Option<(&'static str, &'static str)> {
    match *method {
        hyper::Method::GET => Some(("GetPublicAccessBlock", "s3:GetAccountPublicAccessBlock")),
        hyper::Method::PUT => Some(("PutPublicAccessBlock", "s3:PutAccountPublicAccessBlock")),
        hyper::Method::DELETE => Some(("DeletePublicAccessBlock", "s3:PutAccountPublicAccessBlock")),
        _ => None,
    }
}

/// S3 Control's GetPublicAccessBlock, PutPublicAccessBlock (`body`: its
/// document) or DeletePublicAccessBlock on `account`'s block, which the
/// request is allowed. Put and Delete answer 200, as their model says
/// (botocore's `s3control`: no other response code).
pub async fn control(
    app: &App,
    method: &hyper::Method,
    account: &str,
    body: Option<Bytes>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let empty = || Response::new(Full::new(Bytes::new()));
    Ok(match (method, body) {
        (&hyper::Method::GET, _) => match self::account(&app.pool.get().await?, account).await? {
            Some(block) => xml_ok(block.xml(CONTROL_XMLNS)),
            None => no_such_block(),
        },
        (&hyper::Method::PUT, Some(body)) => match Block::parse(&body) {
            Some(block) => {
                set_account(app, account, Some(block)).await?;
                empty()
            }
            None => malformed(),
        },
        (&hyper::Method::DELETE, _) => {
            set_account(app, account, None).await?;
            empty()
        }
        _ => format_s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed", ""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_blocks() {
        for bits in 0..16 {
            assert_eq!(Block::from_bits(bits).bits(), bits);
        }
        let doc = |inner: &str| format!("<PublicAccessBlockConfiguration>{inner}</PublicAccessBlockConfiguration>");
        let block = Block::parse(doc("<BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>false</IgnorePublicAcls>").as_bytes());
        assert_eq!(block, Some(Block { block_public_policy: true, ..Block::default() }));
        assert_eq!(Block::parse(doc("").as_bytes()), Some(Block::default()));
        for bad in ["<BlockPublicPolicy>yes</BlockPublicPolicy>", "<Other>true</Other>"] {
            assert_eq!(Block::parse(doc(bad).as_bytes()), None, "{bad}");
        }
        assert_eq!(Block::parse(b"<Other/>"), None);
        let xml = Block::from_bits(15).xml(CONTROL_XMLNS);
        assert_eq!(Block::parse(xml.as_bytes()), Some(Block::from_bits(15)));
        assert!(xml.contains("<BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"));
    }
}
