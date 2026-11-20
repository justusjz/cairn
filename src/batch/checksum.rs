//! Batch Operations' `S3ComputeObjectChecksum`: works out a checksum of each
//! version's data at rest, in an algorithm and of a type the job names (see
//! `s3::objects::copy::compute_checksum`), and reports it in the task's
//! line of the completion report, as S3 does: its `ResultMessage`, JSON,
//! `{"checksum_base64":…,"etag":…,"checksumAlgorithm":…,"checksumType":…,
//! "checksum_hex":…}`. Nothing of the version changes, so a task done
//! again does no harm.
//!
//! A COMPOSITE checksum is a multipart object's: the algorithm over its
//! parts' checksums, as S3's are (its base64 and hex are of those bytes,
//! without the `-N` S3's headers add). An object that isn't multipart has
//! only a FULL_OBJECT one, as S3's single PUTs have, and that's what it's
//! reported with. CRC64NVME has no COMPOSITE checksums, as in S3.
//!
//! The job's role must be allowed to read each version (`s3:GetObject`,
//! `s3:GetObjectVersion` for a version named), as S3 asks of it; and, for
//! an SSE-KMS one, to use its key (see `kms`). An SSE-C one's key Cairn
//! doesn't have: its task fails, as S3's does.

use std::sync::Arc;

use http_body_util::Full;
use hyper::{HeaderMap, Method, Response, body::Bytes};
use serde::{Deserialize, Serialize};

use super::{
    control::{bad_request, element, text},
    copy::failure_of,
    manifest::Task,
    report::TaskFailure,
};
use crate::{
    App,
    s3::{
        access::Access,
        checksums::{Algorithm, Type},
    },
    users::Principal,
};

/// What checksums a job works out.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComputeChecksum {
    /// As S3 names it (`CRC32`, `SHA256`, ...).
    pub algorithm: String,
    /// `FULL_OBJECT` or `COMPOSITE`.
    pub kind: String,
}

/// CreateJob's `<S3ComputeObjectChecksum>`: its `ChecksumAlgorithm`, and
/// `ChecksumType` (else `FULL_OBJECT`).
pub(super) fn parse(operation: roxmltree::Node) -> Result<ComputeChecksum, Response<Full<Bytes>>> {
    let Some(name) = text(operation, "ChecksumAlgorithm") else {
        return Err(bad_request("A ChecksumAlgorithm is required."));
    };
    let Some(algorithm) = Algorithm::ALL.into_iter().find(|a| a.name() == name) else {
        return Err(bad_request(&format!("{name} isn't a checksum algorithm.")));
    };
    let kind = match text(operation, "ChecksumType") {
        None => Type::FullObject,
        Some(name) => match [Type::FullObject, Type::Composite]
            .into_iter()
            .find(|t| t.name() == name)
        {
            Some(kind) => kind,
            None => return Err(bad_request("A ChecksumType is FULL_OBJECT or COMPOSITE.")),
        },
    };
    if algorithm == Algorithm::Crc64Nvme && kind == Type::Composite {
        return Err(bad_request("CRC64NVME checksums are FULL_OBJECT only."));
    }
    Ok(ComputeChecksum {
        algorithm: algorithm.name().to_owned(),
        kind: kind.name().to_owned(),
    })
}

impl ComputeChecksum {
    /// It as CreateJob's `<S3ComputeObjectChecksum>`, as DescribeJob tells it.
    pub fn xml(&self) -> String {
        format!(
            "<S3ComputeObjectChecksum>{}{}</S3ComputeObjectChecksum>",
            element("ChecksumAlgorithm", &self.algorithm),
            element("ChecksumType", &self.kind)
        )
    }

    fn algorithm(&self) -> anyhow::Result<Algorithm> {
        Algorithm::from_name(&self.algorithm)
            .ok_or_else(|| anyhow::anyhow!("{} is no checksum algorithm", self.algorithm))
    }

    fn kind(&self) -> anyhow::Result<Type> {
        Type::from_name(&self.kind)
            .ok_or_else(|| anyhow::anyhow!("{} is no checksum type", self.kind))
    }
}

/// Works out the checksum of `task`'s version, as `access` (of the job's
/// role session `principal`, `who`) allows it: its report's message, or why
/// not.
pub(super) async fn run(
    app: &Arc<App>,
    access: &mut Access,
    principal: &Principal,
    who: &str,
    compute: &ComputeChecksum,
    task: &Task,
) -> anyhow::Result<Result<String, TaskFailure>> {
    let query = match &task.version_id {
        Some(v) => format!(
            "versionId={}",
            percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
        ),
        None => String::new(),
    };
    if let Err(failure) = super::authorize(
        app,
        access,
        who,
        &Method::GET,
        &task.bucket,
        &task.key,
        &query,
        &HeaderMap::new(),
    )
    .await?
    {
        return Ok(Err(failure));
    }
    let computed = crate::s3::objects::copy::compute_checksum(
        app,
        &task.bucket,
        &task.key,
        task.version_id.as_deref(),
        compute.algorithm()?,
        compute.kind()?,
        Some(principal.kms_caller()?),
    )
    .await?;
    Ok(match computed {
        Ok(computed) => Ok(message(&computed)),
        Err(refused) => Err(failure_of(refused).await),
    })
}

/// A task's `ResultMessage`, as S3 writes it.
fn message(computed: &crate::s3::objects::copy::Computed) -> String {
    let hex: String = computed.raw.iter().map(|b| format!("{b:02X}")).collect();
    serde_json::json!({
        "checksum_base64": crate::s3::checksums::encode(&computed.raw),
        "etag": computed.etag,
        "checksumAlgorithm": computed.checksum.algorithm.name(),
        "checksumType": computed.checksum.kind.name(),
        "checksum_hex": hex,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3::checksums::Checksum;

    fn parsed(operation: &str) -> Result<ComputeChecksum, u16> {
        let xml = format!("<Operation>{operation}</Operation>");
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let node = doc.root_element().first_element_child().unwrap();
        parse(node).map_err(|r| r.status().as_u16())
    }

    #[test]
    fn computations_are_parsed() {
        let compute = parsed(
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>SHA256</ChecksumAlgorithm>\
             <ChecksumType>COMPOSITE</ChecksumType></S3ComputeObjectChecksum>",
        )
        .unwrap();
        assert_eq!(compute.algorithm().unwrap(), Algorithm::Sha256);
        assert_eq!(compute.kind().unwrap(), Type::Composite);
        assert_eq!(parsed(&compute.xml()).unwrap(), compute);
        let compute = parsed(
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm>\
             </S3ComputeObjectChecksum>",
        )
        .unwrap();
        assert_eq!(compute.kind, "FULL_OBJECT");
        for bad in [
            "<S3ComputeObjectChecksum/>",
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>crc32</ChecksumAlgorithm></S3ComputeObjectChecksum>",
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>CRC32</ChecksumAlgorithm>\
             <ChecksumType>PARTS</ChecksumType></S3ComputeObjectChecksum>",
            "<S3ComputeObjectChecksum><ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm>\
             <ChecksumType>COMPOSITE</ChecksumType></S3ComputeObjectChecksum>",
        ] {
            assert_eq!(parsed(bad), Err(400), "{bad}");
        }
    }

    #[test]
    fn messages_are_s3s() {
        let raw = vec![0x6d, 0x2f, 0x53, 0x39];
        let computed = crate::s3::objects::copy::Computed {
            checksum: Checksum::full(Algorithm::Crc32, &raw),
            raw,
            etag: "3c3c1813042989094598e4b57ecbdc82".to_owned(),
        };
        let message: serde_json::Value = serde_json::from_str(&message(&computed)).unwrap();
        assert_eq!(
            message,
            serde_json::json!({
                "checksum_base64": "bS9TOQ==",
                "etag": "3c3c1813042989094598e4b57ecbdc82",
                "checksumAlgorithm": "CRC32",
                "checksumType": "FULL_OBJECT",
                "checksum_hex": "6D2F5339",
            })
        );
    }
}
