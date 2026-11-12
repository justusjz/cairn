//! Block Public Access: a bucket's public access block
//! (GetPublicAccessBlock, PutPublicAccessBlock, DeletePublicAccessBlock,
//! `?publicAccessBlock`), and the cluster's (the settings
//! `block-public-policy` and `restrict-public-buckets`, S3's account-level
//! block), which count together: a flag is on if either has it.
//!
//! - `BlockPublicPolicy`: a public bucket policy (`Policy::is_public`) is
//!   refused when it's set (`policy`).
//! - `RestrictPublicBuckets`: a bucket's public policy allows anonymous
//!   requests nothing (`access`); the cluster's users keep what it allows
//!   them, as an account's do in S3.
//! - `BlockPublicAcls`, `IgnorePublicAcls`: kept and told, as S3 does; Cairn
//!   refuses every ACL but `private` anyway (`acl`), so both always hold.
//!
//! New buckets have all four, as S3's do since 2023; the buckets made before
//! there were blocks have none.

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

    fn xml(self) -> String {
        let flags: String = self
            .flags()
            .iter()
            .zip(FLAGS)
            .map(|(on, (name, _))| format!("<{name}>{on}</{name}>"))
            .collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{flags}\
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

/// The cluster's own flags, the settings (see the module's doc): its
/// `block-public-policy` and `restrict-public-buckets`.
pub async fn cluster<C: deadpool_postgres::GenericClient>(client: &C) -> anyhow::Result<Block> {
    use crate::settings::{BLOCK_PUBLIC_POLICY, RESTRICT_PUBLIC_BUCKETS};
    Ok(Block {
        block_public_policy: BLOCK_PUBLIC_POLICY.get(client).await? != 0,
        restrict_public_buckets: RESTRICT_PUBLIC_BUCKETS.get(client).await? != 0,
        ..Block::default()
    })
}

fn no_such_bucket() -> Response<Full<Bytes>> {
    format_s3_error(StatusCode::NOT_FOUND, "NoSuchBucket", "the specified bucket does not exist")
}

/// GetPublicAccessBlock.
pub async fn get_public_access_block(app: &App, bucket: &str) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(match get(app, bucket).await? {
        None => no_such_bucket(),
        Some(None) => format_s3_error(
            StatusCode::NOT_FOUND,
            "NoSuchPublicAccessBlockConfiguration",
            "The public access block configuration was not found",
        ),
        Some(Some(block)) => xml_ok(block.xml()),
    })
}

/// PutPublicAccessBlock: replaces the bucket's block with the document's.
/// 200, as in S3.
pub async fn put_public_access_block(app: &App, bucket: &str, body: Bytes) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(block) = Block::parse(&body) else {
        return Ok(format_s3_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema",
        ));
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
        let xml = Block::from_bits(15).xml();
        assert_eq!(Block::parse(xml.as_bytes()), Some(Block::from_bits(15)));
        assert!(xml.contains("<BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls>"));
    }
}
