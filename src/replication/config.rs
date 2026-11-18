//! A bucket's replication configuration, as PutBucketReplication takes it
//! and GetBucketReplication answers it (`<ReplicationConfiguration>`), and
//! as it's kept (JSON, in the bucket's row). What replicating by it does is
//! `replication`'s; which writes it queues, `cairn_replicate`'s (in
//! `catalog.sql`), which reads the JSON: `enabled`, `priority`, `prefix`,
//! `stored_tags`, `destination.bucket`, `delete_markers` and `kms_objects`
//! of each rule.
//!
//! Both of S3's schemas are taken. A rule of the first names a `Prefix` of
//! its own, and replicates delete markers; one of the second a `Filter`
//! (a prefix, a tag, or both in an `And`), a `Priority` and whether it
//! replicates delete markers (`DeleteMarkerReplication`), which it must
//! say. The two don't mix.

use serde::{Deserialize, Serialize};

use crate::s3::{
    tags::{On, Tags},
    util::xml_escape,
};

/// How many rules a configuration may have, as in S3.
pub const MAX_RULES: usize = 1000;
/// The longest rule ID, as in S3.
const MAX_ID: usize = 255;

/// A bucket's replication configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Configuration {
    /// The IAM role it replicates as, by its ARN.
    pub role: String,
    pub rules: Vec<Rule>,
}

/// One of its rules.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    /// Which rule decides where rules overlap: the highest. `None` for a
    /// rule of the first schema, which has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    pub enabled: bool,
    /// What it picks, as it was given.
    pub filter: Filter,
    /// What the filter comes to: a prefix of the key (may be empty), and
    /// tags the version must have, in their stored form (`k=v`, see
    /// `s3::tags`), for `cairn_replicate`.
    pub prefix: String,
    #[serde(default)]
    pub tags: Vec<(String, String)>,
    #[serde(default)]
    pub stored_tags: Vec<String>,
    pub destination: Destination,
    /// Whether it replicates delete markers: as `DeleteMarkerReplication`
    /// says, or always, for a rule of the first schema.
    pub delete_markers: bool,
    /// Whether it replicates SSE-KMS objects (`SseKmsEncryptedObjects`).
    #[serde(default)]
    pub kms_objects: bool,
    /// `ReplicaModifications`, as it was given (`None`: it wasn't), which
    /// is only answered back: changes to a replica's metadata aren't
    /// replicated (nor are a source's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_modifications: Option<bool>,
}

/// How a rule picks the versions it replicates.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Filter {
    /// The first schema's `<Prefix>`.
    Legacy,
    /// `<Filter/>` or `<Filter><Prefix/></Filter>`: the prefix, if it was
    /// given.
    Prefix(Option<String>),
    /// `<Filter><Tag/></Filter>`.
    Tag,
    /// `<Filter><And>…</And></Filter>`: whether it had a prefix.
    And { prefix: bool },
}

/// Where a rule replicates to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Destination {
    /// The bucket, by its name (it's given, and answered, as its ARN).
    pub bucket: String,
    /// The account it expects to own the bucket, if it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The storage class replicas are stored in, if not their source's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Whether replicas are owned by the destination's owner
    /// (`AccessControlTranslation`), which they always are: Cairn's buckets
    /// are all `BucketOwnerEnforced`.
    #[serde(default)]
    pub owner_override: bool,
    /// The KMS key SSE-KMS replicas are encrypted under
    /// (`EncryptionConfiguration`), by its ID as `kms::KeyId` has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key: Option<String>,
}

/// Why a configuration is refused.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// 400 MalformedXML: not the document S3's schema has.
    Malformed(String),
    /// 400 InvalidRequest.
    Request(String),
    /// 400 InvalidArgument.
    Argument(String),
    /// 501 NotImplemented: something Cairn doesn't do.
    Unsupported(String),
}

impl Invalid {
    pub fn response(&self) -> hyper::Response<http_body_util::Full<hyper::body::Bytes>> {
        use crate::s3::util::format_s3_error;
        use hyper::StatusCode;
        match self {
            Invalid::Malformed(_) => format_s3_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ),
            Invalid::Request(message) => format_s3_error(StatusCode::BAD_REQUEST, "InvalidRequest", message),
            Invalid::Argument(message) => format_s3_error(StatusCode::BAD_REQUEST, "InvalidArgument", message),
            Invalid::Unsupported(message) => format_s3_error(StatusCode::NOT_IMPLEMENTED, "NotImplemented", message),
        }
    }
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// `node`'s only child `name`, if it has one; refused if it has several.
fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Option<Node<'a, 'i>>, Invalid> {
    let mut found = node.children().filter(|n| n.is_element() && n.tag_name().name() == name);
    match (found.next(), found.next()) {
        (None, _) => Ok(None),
        (Some(child), None) => Ok(Some(child)),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

fn children<'a, 'i>(node: Node<'a, 'i>, name: &'a str) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    node.children().filter(move |n| n.is_element() && n.tag_name().name() == name)
}

fn text(node: Node) -> String {
    node.text().unwrap_or("").to_owned()
}

fn required<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Node<'a, 'i>, Invalid> {
    child(node, name)?.ok_or_else(|| Invalid::Malformed(format!("{} needs a {name}", node.tag_name().name())))
}

/// Refuses the children of `node` that aren't among `known`.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

/// A `<Status>` child of `node`: Enabled or Disabled.
fn status(node: Node) -> Result<bool, Invalid> {
    only(node, &["Status"])?;
    match text(required(node, "Status")?).as_str() {
        "Enabled" => Ok(true),
        "Disabled" => Ok(false),
        _ => Err(Invalid::Malformed("Status is Enabled or Disabled".to_owned())),
    }
}

/// A `<Tag>`'s key and value.
fn tag(node: Node) -> Result<(String, String), Invalid> {
    only(node, &["Key", "Value"])?;
    Ok((text(required(node, "Key")?), text(required(node, "Value")?)))
}

fn status_name(enabled: bool) -> &'static str {
    if enabled { "Enabled" } else { "Disabled" }
}

/// A bucket's name, from its ARN as a destination names it.
fn bucket_of_arn(arn: &str) -> Option<&str> {
    let name = arn.strip_prefix("arn:aws:s3:::")?;
    (!name.is_empty() && !name.contains('/')).then_some(name)
}

impl Configuration {
    /// Parses a `<ReplicationConfiguration>`, as PutBucketReplication takes
    /// it, and checks it as S3 does (but for what's in the cluster: see
    /// `s3::buckets::replication`).
    pub fn parse(body: &str) -> Result<Configuration, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "ReplicationConfiguration" {
            return Err(Invalid::Malformed("not a ReplicationConfiguration".to_owned()));
        }
        only(root, &["Role", "Rule"])?;
        let role = text(required(root, "Role")?);
        if super::role_account(&role).is_none() {
            return Err(Invalid::Argument("Invalid ReplicationConfiguration Role".to_owned()));
        }
        let mut rules = Vec::new();
        for node in children(root, "Rule") {
            rules.push(Rule::parse(node)?);
        }
        if rules.is_empty() {
            return Err(Invalid::Malformed("a ReplicationConfiguration needs a Rule".to_owned()));
        }
        if rules.len() > MAX_RULES {
            return Err(Invalid::Request(format!("A replication configuration may have at most {MAX_RULES} rules.")));
        }
        let legacy = rules.iter().filter(|r| r.filter == Filter::Legacy).count();
        if legacy != 0 && legacy != rules.len() {
            return Err(Invalid::Request(
                "Rules with a Prefix of their own and rules with a Filter can't be in one configuration.".to_owned(),
            ));
        }
        for (i, rule) in rules.iter().enumerate() {
            if rules[..i].iter().any(|other| other.id == rule.id) {
                return Err(Invalid::Argument("Rule Id must be unique".to_owned()));
            }
            if rule.priority.is_some() && rules[..i].iter().any(|other| other.priority == rule.priority) {
                return Err(Invalid::Request("Found two rules with the same priority".to_owned()));
            }
            // Of the first schema, two rules that pick the same version
            // would have nothing to decide between them.
            if rule.filter == Filter::Legacy
                && rules[..i].iter().any(|other| other.prefix.starts_with(&rule.prefix) || rule.prefix.starts_with(&other.prefix))
            {
                return Err(Invalid::Request("Found overlapping prefixes in rules without priorities".to_owned()));
            }
        }
        Ok(Configuration { role, rules })
    }

    /// The `<ReplicationConfiguration>` GetBucketReplication answers.
    pub fn xml(&self) -> String {
        let mut xml = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Role>{}</Role>",
            xml_escape(&self.role)
        );
        for rule in &self.rules {
            rule.push_xml(&mut xml);
        }
        xml.push_str("</ReplicationConfiguration>");
        xml
    }

    /// The buckets it replicates to, each once.
    pub fn destinations(&self) -> Vec<&Destination> {
        let mut destinations: Vec<&Destination> = Vec::new();
        for rule in &self.rules {
            if !destinations.iter().any(|d| d.bucket == rule.destination.bucket) {
                destinations.push(&rule.destination);
            }
        }
        destinations
    }

    /// The rule `id`, if there's one.
    pub fn rule(&self, id: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a replication configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Configuration> {
        serde_json::from_str(json)
    }
}

impl Rule {
    fn parse(node: Node) -> Result<Rule, Invalid> {
        only(
            node,
            &[
                "ID",
                "Priority",
                "Prefix",
                "Filter",
                "Status",
                "SourceSelectionCriteria",
                "ExistingObjectReplication",
                "Destination",
                "DeleteMarkerReplication",
            ],
        )?;
        let id = match child(node, "ID")? {
            Some(id) => text(id),
            None => uuid::Uuid::new_v4().to_string(),
        };
        if id.chars().count() > MAX_ID {
            return Err(Invalid::Argument(format!("The ID of a rule may be at most {MAX_ID} characters long.")));
        }
        let enabled = match text(required(node, "Status")?).as_str() {
            "Enabled" => true,
            "Disabled" => false,
            _ => return Err(Invalid::Malformed("Status is Enabled or Disabled".to_owned())),
        };
        let priority = match child(node, "Priority")? {
            None => None,
            Some(p) => Some(text(p).trim().parse::<i32>().map_err(|_| Invalid::Malformed("Priority is an integer".to_owned()))?),
        };
        let (filter, prefix, tags) = match (child(node, "Prefix")?, child(node, "Filter")?) {
            (Some(_), Some(_)) => {
                return Err(Invalid::Malformed("a Rule has a Prefix or a Filter, not both".to_owned()));
            }
            (Some(prefix), None) => (Filter::Legacy, text(prefix), Vec::new()),
            (None, Some(filter)) => parse_filter(filter)?,
            (None, None) => {
                return Err(Invalid::Malformed("a Rule needs a Prefix or a Filter".to_owned()));
            }
        };
        let legacy = filter == Filter::Legacy;
        let delete_markers = match (child(node, "DeleteMarkerReplication")?, legacy) {
            (Some(_), true) => {
                return Err(Invalid::Request(
                    "DeleteMarkerReplication is only taken with a Filter: a rule with a Prefix of its own \
                     replicates delete markers."
                        .to_owned(),
                ));
            }
            (None, true) => true,
            (Some(markers), false) => status(markers)?,
            (None, false) => {
                return Err(Invalid::Request(
                    "DeleteMarkerReplication must be specified for this version of Cross Region Replication \
                     configuration schema."
                        .to_owned(),
                ));
            }
        };
        if legacy && priority.is_some() {
            return Err(Invalid::Request("Priority is only taken with a Filter.".to_owned()));
        }
        if delete_markers && !tags.is_empty() {
            return Err(Invalid::Request("Delete marker replication is not supported if any Tag filter is specified.".to_owned()));
        }
        let (mut kms_objects, mut replica_modifications) = (false, None);
        if let Some(criteria) = child(node, "SourceSelectionCriteria")? {
            only(criteria, &["SseKmsEncryptedObjects", "ReplicaModifications"])?;
            if let Some(kms) = child(criteria, "SseKmsEncryptedObjects")? {
                kms_objects = status(kms)?;
            }
            if let Some(modifications) = child(criteria, "ReplicaModifications")? {
                replica_modifications = Some(status(modifications)?);
            }
        }
        if let Some(existing) = child(node, "ExistingObjectReplication")?
            && status(existing)?
        {
            return Err(Invalid::Unsupported(
                "Existing object replication isn't supported: only versions written after a rule is set are replicated."
                    .to_owned(),
            ));
        }
        let destination = Destination::parse(required(node, "Destination")?)?;
        match (kms_objects, &destination.kms_key) {
            (true, None) => {
                return Err(Invalid::Request(
                    "ReplicaKmsKeyID must be specified if SseKmsEncryptedObjects tag is present.".to_owned(),
                ));
            }
            (false, Some(_)) => {
                return Err(Invalid::Request(
                    "SseKmsEncryptedObjects must be specified if EncryptionConfiguration is present.".to_owned(),
                ));
            }
            _ => {}
        }
        let stored_tags = match Tags::from_pairs(tags.clone(), On::Object) {
            Ok(set) => set.stored().split('&').filter(|t| !t.is_empty()).map(str::to_owned).collect(),
            Err(_) => return Err(Invalid::Argument("Duplicate Tag Keys are not allowed.".to_owned())),
        };
        Ok(Rule {
            id,
            priority: if legacy { None } else { Some(priority.unwrap_or(0)) },
            enabled,
            filter,
            prefix,
            tags,
            stored_tags,
            destination,
            delete_markers,
            kms_objects,
            replica_modifications,
        })
    }

    fn push_xml(&self, xml: &mut String) {
        xml.push_str(&format!("<Rule><ID>{}</ID>", xml_escape(&self.id)));
        if let Some(priority) = self.priority {
            xml.push_str(&format!("<Priority>{priority}</Priority>"));
        }
        let tag = |(k, v): &(String, String)| format!("<Tag><Key>{}</Key><Value>{}</Value></Tag>", xml_escape(k), xml_escape(v));
        match &self.filter {
            Filter::Legacy => xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(&self.prefix))),
            Filter::Prefix(None) => xml.push_str("<Filter/>"),
            Filter::Prefix(Some(prefix)) => xml.push_str(&format!("<Filter><Prefix>{}</Prefix></Filter>", xml_escape(prefix))),
            Filter::Tag => xml.push_str(&format!("<Filter>{}</Filter>", self.tags.iter().map(tag).collect::<String>())),
            Filter::And { prefix } => {
                xml.push_str("<Filter><And>");
                if *prefix {
                    xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(&self.prefix)));
                }
                xml.push_str(&self.tags.iter().map(tag).collect::<String>());
                xml.push_str("</And></Filter>");
            }
        }
        xml.push_str(&format!("<Status>{}</Status>", status_name(self.enabled)));
        if self.kms_objects || self.replica_modifications.is_some() {
            xml.push_str("<SourceSelectionCriteria>");
            if self.kms_objects {
                xml.push_str("<SseKmsEncryptedObjects><Status>Enabled</Status></SseKmsEncryptedObjects>");
            }
            if let Some(modifications) = self.replica_modifications {
                xml.push_str(&format!(
                    "<ReplicaModifications><Status>{}</Status></ReplicaModifications>",
                    status_name(modifications)
                ));
            }
            xml.push_str("</SourceSelectionCriteria>");
        }
        self.destination.push_xml(xml);
        if self.filter != Filter::Legacy {
            xml.push_str(&format!(
                "<DeleteMarkerReplication><Status>{}</Status></DeleteMarkerReplication>",
                status_name(self.delete_markers)
            ));
        }
        xml.push_str("</Rule>");
    }
}

/// A rule's `<Filter>`: what it is, its prefix, and its tags.
/// A filter, its prefix, and its tags.
type Parsed = (Filter, String, Vec<(String, String)>);

fn parse_filter(filter: Node) -> Result<Parsed, Invalid> {
    only(filter, &["Prefix", "Tag", "And"])?;
    let (prefix, tag_node, and) = (child(filter, "Prefix")?, child(filter, "Tag")?, child(filter, "And")?);
    match (prefix, tag_node, and) {
        (None, None, None) => Ok((Filter::Prefix(None), String::new(), Vec::new())),
        (Some(prefix), None, None) => Ok((Filter::Prefix(Some(text(prefix))), text(prefix), Vec::new())),
        (None, Some(t), None) => Ok((Filter::Tag, String::new(), vec![tag(t)?])),
        (None, None, Some(and)) => {
            only(and, &["Prefix", "Tag"])?;
            let prefix = child(and, "Prefix")?;
            let tags = children(and, "Tag").map(tag).collect::<Result<Vec<_>, _>>()?;
            if tags.is_empty() || (prefix.is_none() && tags.len() < 2) {
                return Err(Invalid::Malformed("an And has a Prefix and Tags, or two Tags at least".to_owned()));
            }
            Ok((Filter::And { prefix: prefix.is_some() }, prefix.map(text).unwrap_or_default(), tags))
        }
        _ => Err(Invalid::Malformed("a Filter has one of Prefix, Tag and And".to_owned())),
    }
}

impl Destination {
    fn parse(node: Node) -> Result<Destination, Invalid> {
        only(
            node,
            &["Bucket", "Account", "StorageClass", "AccessControlTranslation", "EncryptionConfiguration", "ReplicationTime", "Metrics"],
        )?;
        let arn = text(required(node, "Bucket")?);
        let Some(bucket) = bucket_of_arn(&arn) else {
            return Err(Invalid::Argument("Invalid bucket ARN".to_owned()));
        };
        let account = child(node, "Account")?.map(text);
        let storage_class = child(node, "StorageClass")?.map(text);
        let owner_override = match child(node, "AccessControlTranslation")? {
            None => false,
            Some(translation) => {
                only(translation, &["Owner"])?;
                if text(required(translation, "Owner")?) != "Destination" {
                    return Err(Invalid::Malformed("AccessControlTranslation's Owner is Destination".to_owned()));
                }
                if account.is_none() {
                    return Err(Invalid::Request(
                        "Destination Account must be specified with AccessControlTranslation.".to_owned(),
                    ));
                }
                true
            }
        };
        let kms_key = match child(node, "EncryptionConfiguration")? {
            None => None,
            Some(encryption) => {
                only(encryption, &["ReplicaKmsKeyID"])?;
                let given = text(required(encryption, "ReplicaKmsKeyID")?);
                match crate::kms::KeyId::parse(given.strip_prefix("arn:aws:kms:").unwrap_or(&given)) {
                    Some(key) => Some(key.as_string()),
                    None => return Err(Invalid::Argument("Invalid ReplicaKmsKeyID".to_owned())),
                }
            }
        };
        for unsupported in ["ReplicationTime", "Metrics"] {
            if let Some(node) = child(node, unsupported)?
                && child(node, "Status")?.is_some_and(|s| text(s) == "Enabled")
            {
                return Err(Invalid::Unsupported(format!(
                    "{unsupported} isn't supported: replication within the cluster has no time control or metrics."
                )));
            }
        }
        Ok(Destination { bucket: bucket.to_owned(), account, storage_class, owner_override, kms_key })
    }

    fn push_xml(&self, xml: &mut String) {
        xml.push_str(&format!("<Destination><Bucket>arn:aws:s3:::{}</Bucket>", xml_escape(&self.bucket)));
        if let Some(account) = &self.account {
            xml.push_str(&format!("<Account>{}</Account>", xml_escape(account)));
        }
        if let Some(class) = &self.storage_class {
            xml.push_str(&format!("<StorageClass>{}</StorageClass>", xml_escape(class)));
        }
        if self.owner_override {
            xml.push_str("<AccessControlTranslation><Owner>Destination</Owner></AccessControlTranslation>");
        }
        if let Some(key) = &self.kms_key {
            xml.push_str(&format!(
                "<EncryptionConfiguration><ReplicaKmsKeyID>arn:aws:kms:{}</ReplicaKmsKeyID></EncryptionConfiguration>",
                xml_escape(key)
            ));
        }
        xml.push_str("</Destination>");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLE: &str = "<Role>arn:aws:iam::123456789012:role/replication</Role>";

    fn doc(rules: &str) -> String {
        format!("<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{ROLE}{rules}</ReplicationConfiguration>")
    }

    const DEST: &str = "<Destination><Bucket>arn:aws:s3:::backup</Bucket></Destination>";

    #[test]
    fn a_filtered_rule_round_trips() {
        let body = doc(&format!(
            "<Rule><ID>docs</ID><Priority>2</Priority><Filter><And><Prefix>docs/</Prefix>\
             <Tag><Key>team</Key><Value>a b</Value></Tag></And></Filter><Status>Enabled</Status>{DEST}\
             <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication></Rule>"
        ));
        let config = Configuration::parse(&body).unwrap();
        let rule = &config.rules[0];
        assert_eq!(rule.prefix, "docs/");
        assert_eq!(rule.stored_tags, vec!["team=a%20b".to_owned()]);
        assert_eq!(rule.priority, Some(2));
        assert!(!rule.delete_markers);
        assert_eq!(Configuration::parse(&config.xml()).unwrap(), config);
        assert_eq!(Configuration::from_json(&config.to_json()).unwrap(), config);
    }

    #[test]
    fn a_legacy_rule_replicates_delete_markers() {
        let config = Configuration::parse(&doc(&format!("<Rule><Prefix>logs/</Prefix><Status>Enabled</Status>{DEST}</Rule>"))).unwrap();
        let rule = &config.rules[0];
        assert!(rule.delete_markers);
        assert_eq!(rule.priority, None);
        assert_eq!(rule.prefix, "logs/");
        assert!(!rule.id.is_empty());
        assert!(config.xml().contains("<Prefix>logs/</Prefix>"));
        assert!(!config.xml().contains("DeleteMarkerReplication"));
    }

    #[test]
    fn what_s3_refuses_is_refused() {
        let refused = |rules: &str| Configuration::parse(&doc(rules)).unwrap_err();
        // A filtered rule must say whether it replicates delete markers.
        assert!(matches!(refused(&format!("<Rule><Filter/><Status>Enabled</Status>{DEST}</Rule>")), Invalid::Request(_)));
        // Not with a tag filter.
        assert!(matches!(
            refused(&format!(
                "<Rule><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status>{DEST}\
                 <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication></Rule>"
            )),
            Invalid::Request(_)
        ));
        let markers = "<DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>";
        // Same IDs, same priorities.
        let rule = |id: &str, priority: i32| {
            format!("<Rule><ID>{id}</ID><Priority>{priority}</Priority><Filter/><Status>Enabled</Status>{DEST}{markers}</Rule>")
        };
        assert!(matches!(refused(&(rule("a", 1) + &rule("a", 2))), Invalid::Argument(_)));
        assert!(matches!(refused(&(rule("a", 1) + &rule("b", 1))), Invalid::Request(_)));
        // The two schemas don't mix.
        assert!(matches!(
            refused(&(rule("a", 1) + &format!("<Rule><Prefix>x</Prefix><Status>Enabled</Status>{DEST}</Rule>"))),
            Invalid::Request(_)
        ));
        // A destination by its ARN.
        assert!(matches!(
            refused(&format!("<Rule><Filter/><Status>Enabled</Status><Destination><Bucket>backup</Bucket></Destination>{markers}</Rule>")),
            Invalid::Argument(_)
        ));
        // SSE-KMS objects need a key for their replicas.
        assert!(matches!(
            refused(&format!(
                "<Rule><Filter/><Status>Enabled</Status><SourceSelectionCriteria><SseKmsEncryptedObjects>\
                 <Status>Enabled</Status></SseKmsEncryptedObjects></SourceSelectionCriteria>{DEST}{markers}</Rule>"
            )),
            Invalid::Request(_)
        ));
        // What Cairn doesn't do.
        assert!(matches!(
            refused(&format!(
                "<Rule><Filter/><Status>Enabled</Status><ExistingObjectReplication><Status>Enabled</Status>\
                 </ExistingObjectReplication>{DEST}{markers}</Rule>"
            )),
            Invalid::Unsupported(_)
        ));
        assert!(matches!(refused(""), Invalid::Malformed(_)));
        let bad_role = "<ReplicationConfiguration><Role>replication</Role></ReplicationConfiguration>";
        assert!(matches!(Configuration::parse(bad_role).unwrap_err(), Invalid::Argument(_)));
    }

    #[test]
    fn destinations_are_listed_once() {
        let markers = "<DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>";
        let rules = format!(
            "<Rule><ID>a</ID><Priority>1</Priority><Filter><Prefix>a</Prefix></Filter><Status>Enabled</Status>{DEST}{markers}</Rule>\
             <Rule><ID>b</ID><Priority>2</Priority><Filter><Prefix>b</Prefix></Filter><Status>Enabled</Status>{DEST}{markers}</Rule>"
        );
        let config = Configuration::parse(&doc(&rules)).unwrap();
        assert_eq!(config.destinations().len(), 1);
    }
}
