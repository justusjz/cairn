//! Batch Operations' `S3PutObjectAcl`: sets each version's ACL, as
//! PutObjectAcl does (see `s3::acl`), to a canned ACL
//! (`CannedAccessControlList`) or to grants (`AccessControlList`), each task
//! made the PutObjectAcl request it is: of the canned ACL's `x-amz-acl`, or
//! of the grants as its `<AccessControlPolicy>` body. So it's refused where
//! PutObjectAcl is: in a bucket with ACLs disabled (Object Ownership
//! `BucketOwnerEnforced`, new buckets'), a public ACL where BlockPublicAcls
//! blocks it, an owner named that isn't the version's, a grantee by e-mail
//! address (Cairn's accounts have none).

use std::sync::Arc;

use http_body_util::Full;
use hyper::{HeaderMap, Method, Response, body::Bytes, header::HeaderValue};
use serde::{Deserialize, Serialize};

use super::{
    control::{bad_request, child, children, element, text},
    copy::failure_of,
    manifest::Task,
    report::TaskFailure,
};
use crate::{App, s3::access::Access, s3::util::xml_escape};

/// The canned ACLs a job may set (`CannedAccessControlList`): S3's, but
/// for `log-delivery-write`, which is a bucket's.
const CANNED: &[&str] = &[
    "private",
    "public-read",
    "public-read-write",
    "aws-exec-read",
    "authenticated-read",
    "bucket-owner-read",
    "bucket-owner-full-control",
];
/// What grantees are named by (`TypeIdentifier`).
const TYPES: &[&str] = &["id", "emailAddress", "uri"];
const PERMISSIONS: &[&str] = &["FULL_CONTROL", "READ", "WRITE", "READ_ACP", "WRITE_ACP"];
/// The most grants an ACL has, as in S3.
const MAX_GRANTS: usize = 100;

/// What a job sets each version's ACL to.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SetAcl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canned: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list: Option<List>,
}

/// An `AccessControlList`: its owner, and grants.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct List {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    #[serde(default)]
    pub grants: Vec<Grant>,
}

/// An `S3Grant`: its grantee, by `kind` (`TypeIdentifier`), and permission.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub kind: String,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub permission: String,
}

/// CreateJob's `<S3PutObjectAcl>`: its `AccessControlPolicy`, of a canned
/// ACL or a list, not both.
pub(super) fn parse(operation: roxmltree::Node) -> Result<SetAcl, Response<Full<Bytes>>> {
    let Some(policy) = child(operation, "AccessControlPolicy") else {
        return Err(bad_request("An AccessControlPolicy is required."));
    };
    let canned = text(policy, "CannedAccessControlList").map(str::to_owned);
    if let Some(canned) = &canned
        && !CANNED.contains(&canned.as_str())
    {
        return Err(bad_request(&format!("{canned} isn't a canned ACL.")));
    }
    let list = match child(policy, "AccessControlList") {
        None => None,
        Some(list) => {
            let Some(owner) = child(list, "Owner") else {
                return Err(bad_request("An AccessControlList's Owner is required."));
            };
            let mut grants = Vec::new();
            for grant in child(list, "Grants").into_iter().flat_map(children) {
                let grantee = child(grant, "Grantee");
                let field = |name| grantee.and_then(|g| text(g, name)).map(str::to_owned);
                let (Some(kind), Some(identifier)) = (field("TypeIdentifier"), field("Identifier"))
                else {
                    return Err(bad_request(
                        "A grant's Grantee must have a TypeIdentifier and an Identifier.",
                    ));
                };
                if !TYPES.contains(&kind.as_str()) {
                    return Err(bad_request(
                        "A grantee's TypeIdentifier is id, emailAddress or uri.",
                    ));
                }
                let permission = text(grant, "Permission").unwrap_or("");
                if !PERMISSIONS.contains(&permission) {
                    return Err(bad_request(
                        "A grant's Permission is FULL_CONTROL, READ, WRITE, READ_ACP or WRITE_ACP.",
                    ));
                }
                grants.push(Grant {
                    kind,
                    identifier,
                    display_name: field("DisplayName"),
                    permission: permission.to_owned(),
                });
            }
            if grants.len() > MAX_GRANTS {
                return Err(bad_request(&format!(
                    "An AccessControlList has at most {MAX_GRANTS} grants."
                )));
            }
            Some(List {
                owner_id: text(owner, "ID").map(str::to_owned),
                owner_name: text(owner, "DisplayName").map(str::to_owned),
                grants,
            })
        }
    };
    match (&canned, &list) {
        (Some(_), Some(_)) => Err(bad_request(
            "An AccessControlPolicy has an AccessControlList or a CannedAccessControlList, not both.",
        )),
        (None, None) => Err(bad_request(
            "An AccessControlPolicy needs an AccessControlList or a CannedAccessControlList.",
        )),
        _ => Ok(SetAcl { canned, list }),
    }
}

impl SetAcl {
    /// It as CreateJob's `<S3PutObjectAcl>`, as DescribeJob tells it.
    pub fn xml(&self) -> String {
        let mut out = String::from("<S3PutObjectAcl><AccessControlPolicy>");
        if let Some(list) = &self.list {
            out.push_str("<AccessControlList><Grants>");
            for grant in &list.grants {
                out.push_str("<member><Grantee>");
                if let Some(name) = &grant.display_name {
                    out.push_str(&element("DisplayName", name));
                }
                out.push_str(&element("Identifier", &grant.identifier));
                out.push_str(&element("TypeIdentifier", &grant.kind));
                out.push_str("</Grantee>");
                out.push_str(&element("Permission", &grant.permission));
                out.push_str("</member>");
            }
            out.push_str("</Grants><Owner>");
            if let Some(name) = &list.owner_name {
                out.push_str(&element("DisplayName", name));
            }
            if let Some(id) = &list.owner_id {
                out.push_str(&element("ID", id));
            }
            out.push_str("</Owner></AccessControlList>");
        }
        if let Some(canned) = &self.canned {
            out.push_str(&element("CannedAccessControlList", canned));
        }
        out.push_str("</AccessControlPolicy></S3PutObjectAcl>");
        out
    }

    /// The headers of the PutObjectAcl request a task is: a canned ACL's
    /// `x-amz-acl`.
    pub fn headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(canned) = &self.canned {
            headers.insert(
                "x-amz-acl",
                HeaderValue::from_str(canned).expect("a canned ACL is a header value"),
            );
        }
        headers
    }

    /// The body of the PutObjectAcl request a task is: its list's
    /// `<AccessControlPolicy>`, as S3's API has it; nothing for a canned ACL.
    pub fn body(&self) -> String {
        let Some(list) = &self.list else {
            return String::new();
        };
        let mut grants = String::new();
        for grant in &list.grants {
            let (kind, name) = match grant.kind.as_str() {
                "id" => ("CanonicalUser", "ID"),
                "uri" => ("Group", "URI"),
                _ => ("AmazonCustomerByEmail", "EmailAddress"),
            };
            grants.push_str(&format!(
                "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"{kind}\">\
                 <{name}>{}</{name}></Grantee><Permission>{}</Permission></Grant>",
                xml_escape(&grant.identifier),
                grant.permission
            ));
        }
        let owner = list
            .owner_id
            .as_deref()
            .map_or(String::new(), |id| element("ID", id));
        format!(
            "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Owner>{owner}</Owner><AccessControlList>{grants}</AccessControlList>\
             </AccessControlPolicy>"
        )
    }
}

/// Sets `task`'s version's ACL, as `access` (of the job's role session,
/// `who`, made with `SetAcl::headers`) allows it; why not, if it didn't.
pub(super) async fn run(
    app: &Arc<App>,
    access: &mut Access,
    who: &str,
    acl: &SetAcl,
    task: &Task,
) -> anyhow::Result<Result<(), TaskFailure>> {
    let headers = acl.headers();
    let query = match &task.version_id {
        Some(v) => format!(
            "acl&versionId={}",
            percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
        ),
        None => "acl".to_owned(),
    };
    if let Err(failure) = super::authorize(
        app,
        access,
        who,
        &Method::PUT,
        &task.bucket,
        &task.key,
        &query,
        &headers,
    )
    .await?
    {
        return Ok(Err(failure));
    }
    let response = crate::s3::acl::put_object_acl(
        app,
        &task.bucket,
        &task.key,
        task.version_id.as_deref(),
        &headers,
        acl.body().as_bytes(),
    )
    .await?;
    Ok(match response.status().is_success() {
        true => Ok(()),
        false => Err(failure_of(response).await),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(operation: &str) -> Result<SetAcl, u16> {
        let xml = format!("<Operation>{operation}</Operation>");
        let doc = roxmltree::Document::parse(&xml).unwrap();
        let node = doc.root_element().first_element_child().unwrap();
        parse(node).map_err(|r| r.status().as_u16())
    }

    #[test]
    fn canned_acls_are_parsed() {
        let acl = parsed(
            "<S3PutObjectAcl><AccessControlPolicy><CannedAccessControlList>public-read\
             </CannedAccessControlList></AccessControlPolicy></S3PutObjectAcl>",
        )
        .unwrap();
        assert_eq!(acl.canned.as_deref(), Some("public-read"));
        assert_eq!(acl.headers()["x-amz-acl"], "public-read");
        assert_eq!(acl.body(), "");
        assert_eq!(parsed(&acl.xml()).unwrap(), acl);
    }

    #[test]
    fn lists_are_parsed_and_made_bodies() {
        let acl = parsed(
            "<S3PutObjectAcl><AccessControlPolicy><AccessControlList>\
             <Grants><member><Grantee><Identifier>abc</Identifier><TypeIdentifier>id</TypeIdentifier>\
             </Grantee><Permission>READ</Permission></member>\
             <S3Grant><Grantee><Identifier>http://acs.amazonaws.com/groups/global/AllUsers</Identifier>\
             <TypeIdentifier>uri</TypeIdentifier></Grantee><Permission>READ_ACP</Permission></S3Grant></Grants>\
             <Owner><ID>owner</ID></Owner></AccessControlList></AccessControlPolicy></S3PutObjectAcl>",
        )
        .unwrap();
        let list = acl.list.as_ref().unwrap();
        assert_eq!(list.owner_id.as_deref(), Some("owner"));
        assert_eq!(list.grants.len(), 2);
        assert_eq!(list.grants[1].kind, "uri");
        assert!(acl.headers().is_empty());
        let body = acl.body();
        assert!(body.contains("xsi:type=\"CanonicalUser\"><ID>abc</ID>"));
        assert!(body.contains(
            "xsi:type=\"Group\"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>"
        ));
        assert!(body.contains("<Owner><ID>owner</ID></Owner>"));
        assert_eq!(parsed(&acl.xml()).unwrap(), acl);
    }

    #[test]
    fn bad_acls_are_refused() {
        let policy = |inner: &str| {
            format!(
                "<S3PutObjectAcl><AccessControlPolicy>{inner}</AccessControlPolicy></S3PutObjectAcl>"
            )
        };
        assert_eq!(parsed("<S3PutObjectAcl/>"), Err(400));
        assert_eq!(parsed(&policy("")), Err(400));
        assert_eq!(
            parsed(&policy(
                "<CannedAccessControlList>log-delivery-write</CannedAccessControlList>"
            )),
            Err(400)
        );
        // Both.
        assert_eq!(
            parsed(&policy(
                "<CannedAccessControlList>private</CannedAccessControlList>\
                 <AccessControlList><Owner/></AccessControlList>"
            )),
            Err(400)
        );
        // No owner.
        assert_eq!(
            parsed(&policy("<AccessControlList><Grants/></AccessControlList>")),
            Err(400)
        );
        let grant = |grantee: &str, permission: &str| {
            policy(&format!(
                "<AccessControlList><Owner/><Grants><member><Grantee>{grantee}</Grantee>\
                 <Permission>{permission}</Permission></member></Grants></AccessControlList>"
            ))
        };
        let id = "<Identifier>a</Identifier><TypeIdentifier>id</TypeIdentifier>";
        assert!(parsed(&grant(id, "READ")).is_ok());
        assert_eq!(parsed(&grant(id, "EVERYTHING")), Err(400));
        assert_eq!(
            parsed(&grant(
                "<Identifier>a</Identifier><TypeIdentifier>arn</TypeIdentifier>",
                "READ"
            )),
            Err(400)
        );
        assert_eq!(
            parsed(&grant("<TypeIdentifier>id</TypeIdentifier>", "READ")),
            Err(400)
        );
    }
}
