//! An inventory configuration, as PutBucketInventoryConfiguration takes it
//! and GetBucketInventoryConfiguration answers it (`<InventoryConfiguration>`),
//! and as it's kept (JSON). What a report of it holds, and where it goes, is
//! `inventory`'s.

use serde::{Deserialize, Serialize};

use crate::s3::util::xml_escape;

use super::parquet;

/// How many configurations a bucket may have, as in S3.
pub const MAX_PER_BUCKET: i32 = 1000;

/// A bucket's inventory configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Configuration {
    pub id: String,
    pub enabled: bool,
    pub destination: Destination,
    /// Only keys with this prefix (`Filter`), if there's one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Every version and delete marker (`All`), or only the current
    /// objects (`Current`).
    pub all_versions: bool,
    /// The optional fields, in the order they were given (and are answered
    /// in): a report has them in `Field::ALL`'s order.
    #[serde(default)]
    pub fields: Vec<Field>,
    pub frequency: Frequency,
}

/// Where its reports go (`S3BucketDestination`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Destination {
    /// The account it expects to own the bucket, if it says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// The bucket, by its name (it's given, and answered, as its ARN).
    pub bucket: String,
    /// What's put before every report's keys, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
    /// What its reports' data files are (CSV, if it was kept before Cairn
    /// had others).
    #[serde(default)]
    pub format: Format,
}

/// What a report's data files are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    /// Gzipped CSV.
    #[default]
    Csv,
    Parquet,
}

impl Format {
    /// As `<Format>` and the manifest's `fileFormat` have it.
    pub fn name(self) -> &'static str {
        match self {
            Format::Csv => "CSV",
            Format::Parquet => "Parquet",
        }
    }
}

/// How a report's files are encrypted, besides what the destination's
/// default encryption does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Encryption {
    S3,
    /// SSE-KMS, under this key (its ID, as `kms::KeyId` has it).
    Kms(String),
}

/// How often reports are made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frequency {
    Daily,
    Weekly,
}

/// An optional field (a column of the report, after the bucket, key and
/// version columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Field {
    Size,
    LastModifiedDate,
    ETag,
    StorageClass,
    IsMultipartUploaded,
    ReplicationStatus,
    EncryptionStatus,
    ObjectLockRetainUntilDate,
    ObjectLockMode,
    ObjectLockLegalHoldStatus,
    IntelligentTieringAccessTier,
    BucketKeyStatus,
    ChecksumAlgorithm,
    ObjectAccessControlList,
    ObjectOwner,
    ObjectLockEventHoldStatus,
    ObjectLockEventHoldDuration,
    LifecycleExpirationDate,
}

impl Field {
    /// Every field, in the order a report's columns are: that of S3's
    /// documented CSV schema, and then the ones it leaves out of it (event
    /// holds, and the lifecycle expiration date).
    pub const ALL: [Field; 18] = [
        Field::Size,
        Field::LastModifiedDate,
        Field::ETag,
        Field::StorageClass,
        Field::IsMultipartUploaded,
        Field::ReplicationStatus,
        Field::EncryptionStatus,
        Field::ObjectLockRetainUntilDate,
        Field::ObjectLockMode,
        Field::ObjectLockLegalHoldStatus,
        Field::IntelligentTieringAccessTier,
        Field::BucketKeyStatus,
        Field::ChecksumAlgorithm,
        Field::ObjectAccessControlList,
        Field::ObjectOwner,
        Field::ObjectLockEventHoldStatus,
        Field::ObjectLockEventHoldDuration,
        Field::LifecycleExpirationDate,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Field::Size => "Size",
            Field::LastModifiedDate => "LastModifiedDate",
            Field::ETag => "ETag",
            Field::StorageClass => "StorageClass",
            Field::IsMultipartUploaded => "IsMultipartUploaded",
            Field::ReplicationStatus => "ReplicationStatus",
            Field::EncryptionStatus => "EncryptionStatus",
            Field::ObjectLockRetainUntilDate => "ObjectLockRetainUntilDate",
            Field::ObjectLockMode => "ObjectLockMode",
            Field::ObjectLockLegalHoldStatus => "ObjectLockLegalHoldStatus",
            Field::IntelligentTieringAccessTier => "IntelligentTieringAccessTier",
            Field::BucketKeyStatus => "BucketKeyStatus",
            Field::ChecksumAlgorithm => "ChecksumAlgorithm",
            Field::ObjectAccessControlList => "ObjectAccessControlList",
            Field::ObjectOwner => "ObjectOwner",
            Field::ObjectLockEventHoldStatus => "ObjectLockEventHoldStatus",
            Field::ObjectLockEventHoldDuration => "ObjectLockEventHoldDuration",
            Field::LifecycleExpirationDate => "LifecycleExpirationDate",
        }
    }

    fn from_name(name: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.name() == name)
    }
}

/// Why a configuration is refused.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// It doesn't follow S3's schema: `MalformedXML`.
    Malformed(String),
    /// A value S3 refuses: `InvalidArgument`.
    Argument(String),
    /// What S3 has and Cairn doesn't (ORC): `NotImplemented`.
    Unsupported(String),
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    node.children().filter(|n| n.tag_name().name() == name).collect()
}

/// `node`'s only child `name`, if it has one; `Err` if it has several.
fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Option<Node<'a, 'i>>, Invalid> {
    match &children(node, name)[..] {
        [] => Ok(None),
        [child] => Ok(Some(*child)),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

fn text(node: Node, name: &str) -> Result<Option<String>, Invalid> {
    Ok(child(node, name)?.map(|n| n.text().unwrap_or("").to_owned()))
}

fn required_child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Result<Node<'a, 'i>, Invalid> {
    child(node, name)?.ok_or_else(|| Invalid::Malformed(format!("{} needs a {name}", node.tag_name().name())))
}

fn required(node: Node, name: &str) -> Result<String, Invalid> {
    text(node, name)?.ok_or_else(|| Invalid::Malformed(format!("{} needs a {name}", node.tag_name().name())))
}

/// Refuses the children of `node` that aren't among `known`.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

/// Whether `id` is a configuration ID Cairn takes: 1 to 64 letters, digits,
/// `.`, `-` and `_`, as S3 takes its metrics' and analytics' (it's part of
/// every key of the configuration's reports).
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

impl Configuration {
    /// Parses an `<InventoryConfiguration>`, as PutBucketInventoryConfiguration
    /// takes it.
    pub fn parse(body: &str) -> Result<Configuration, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "InventoryConfiguration" {
            return Err(Invalid::Malformed("not an InventoryConfiguration".to_owned()));
        }
        only(
            root,
            &["Destination", "IsEnabled", "Filter", "Id", "IncludedObjectVersions", "OptionalFields", "Schedule"],
        )?;
        let id = required(root, "Id")?;
        if !valid_id(&id) {
            return Err(Invalid::Argument(
                "The configuration ID is 1 to 64 letters, digits, periods, hyphens and underscores".to_owned(),
            ));
        }
        let enabled = match required(root, "IsEnabled")?.trim() {
            "true" => true,
            "false" => false,
            _ => return Err(Invalid::Malformed("IsEnabled is true or false".to_owned())),
        };
        let all_versions = match required(root, "IncludedObjectVersions")?.as_str() {
            "All" => true,
            "Current" => false,
            _ => return Err(Invalid::Malformed("IncludedObjectVersions is All or Current".to_owned())),
        };
        let schedule = required_child(root, "Schedule")?;
        only(schedule, &["Frequency"])?;
        let frequency = match required(schedule, "Frequency")?.as_str() {
            "Daily" => Frequency::Daily,
            "Weekly" => Frequency::Weekly,
            _ => return Err(Invalid::Malformed("Frequency is Daily or Weekly".to_owned())),
        };
        let prefix = match child(root, "Filter")? {
            None => None,
            Some(filter) => {
                only(filter, &["Prefix"])?;
                Some(required(filter, "Prefix")?)
            }
        };
        let mut fields = Vec::new();
        if let Some(optional) = child(root, "OptionalFields")? {
            only(optional, &["Field"])?;
            for node in children(optional, "Field") {
                let name = node.text().unwrap_or("");
                let field = Field::from_name(name)
                    .ok_or_else(|| Invalid::Malformed(format!("{name} isn't an inventory field")))?;
                if fields.contains(&field) {
                    return Err(Invalid::Argument(format!("The field {name} is listed more than once")));
                }
                fields.push(field);
            }
        }
        let destination = required_child(root, "Destination")?;
        only(destination, &["S3BucketDestination"])?;
        let destination = Destination::parse(required_child(destination, "S3BucketDestination")?)?;
        Ok(Configuration { id, enabled, destination, prefix, all_versions, fields, frequency })
    }

    /// As GetBucketInventoryConfiguration answers it (without the XML
    /// declaration and namespace: see `to_xml`).
    fn element(&self) -> String {
        let mut xml = String::from("<InventoryConfiguration>");
        xml.push_str(&self.destination.to_xml());
        xml.push_str(&format!("<IsEnabled>{}</IsEnabled>", self.enabled));
        if let Some(prefix) = &self.prefix {
            xml.push_str(&format!("<Filter><Prefix>{}</Prefix></Filter>", xml_escape(prefix)));
        }
        xml.push_str(&format!("<Id>{}</Id>", xml_escape(&self.id)));
        let versions = if self.all_versions { "All" } else { "Current" };
        xml.push_str(&format!("<IncludedObjectVersions>{versions}</IncludedObjectVersions>"));
        if !self.fields.is_empty() {
            xml.push_str("<OptionalFields>");
            for field in &self.fields {
                xml.push_str(&format!("<Field>{}</Field>", field.name()));
            }
            xml.push_str("</OptionalFields>");
        }
        let frequency = match self.frequency {
            Frequency::Daily => "Daily",
            Frequency::Weekly => "Weekly",
        };
        xml.push_str(&format!("<Schedule><Frequency>{frequency}</Frequency></Schedule>"));
        xml.push_str("</InventoryConfiguration>");
        xml
    }

    /// GetBucketInventoryConfiguration's body.
    pub fn to_xml(&self) -> String {
        let element = self.element();
        let element = element.strip_prefix("<InventoryConfiguration>").expect("it starts so");
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{element}"
        )
    }

    /// ListBucketInventoryConfigurations' body, for a page of `configs`:
    /// `token` is the request's continuation token, `next` the next page's,
    /// if there's one.
    pub fn list_xml(configs: &[Configuration], token: Option<&str>, next: Option<&str>) -> String {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListInventoryConfigurationsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        if let Some(token) = token {
            xml.push_str(&format!("<ContinuationToken>{}</ContinuationToken>", xml_escape(token)));
        }
        for config in configs {
            xml.push_str(&config.element());
        }
        xml.push_str(&format!("<IsTruncated>{}</IsTruncated>", next.is_some()));
        if let Some(next) = next {
            xml.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", xml_escape(next)));
        }
        xml.push_str("</ListInventoryConfigurationsResult>");
        xml
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Configuration> {
        serde_json::from_str(json)
    }

    /// The report's columns: the bucket, key and (for all versions) the
    /// version's, then its optional fields, in their order.
    pub fn columns(&self) -> Vec<Column> {
        let mut columns = vec![Column::Bucket, Column::Key];
        if self.all_versions {
            columns.extend([Column::VersionId, Column::IsLatest, Column::IsDeleteMarker]);
        }
        for field in Field::ALL {
            if self.fields.contains(&field) {
                columns.push(Column::Field(field));
                // Its unit, in a column of its own (S3's user guide).
                if field == Field::ObjectLockEventHoldDuration {
                    columns.push(Column::EventHoldDurationUnit);
                }
            }
        }
        columns
    }
}

/// A column of a report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Column {
    Bucket,
    Key,
    VersionId,
    IsLatest,
    IsDeleteMarker,
    Field(Field),
    EventHoldDurationUnit,
}

impl Column {
    /// Its name in the manifest's `fileSchema`.
    pub fn name(self) -> &'static str {
        match self {
            Column::Bucket => "Bucket",
            Column::Key => "Key",
            Column::VersionId => "VersionId",
            Column::IsLatest => "IsLatest",
            Column::IsDeleteMarker => "IsDeleteMarker",
            Column::Field(field) => field.name(),
            Column::EventHoldDurationUnit => "ObjectLockEventHoldDurationUnit",
        }
    }

    /// Its column of a Parquet file: its name and type, as S3's schema has
    /// them (the bucket and key are the only required ones).
    pub fn parquet(self) -> parquet::Column {
        use parquet::Type::{Boolean, Int32, Int64, Text, Timestamp};
        let (name, ty) = match self {
            Column::Bucket => ("bucket", Text),
            Column::Key => ("key", Text),
            Column::VersionId => ("version_id", Text),
            Column::IsLatest => ("is_latest", Boolean),
            Column::IsDeleteMarker => ("is_delete_marker", Boolean),
            Column::EventHoldDurationUnit => ("object_lock_event_hold_duration_unit", Text),
            Column::Field(field) => match field {
                Field::Size => ("size", Int64),
                Field::LastModifiedDate => ("last_modified_date", Timestamp),
                Field::ETag => ("e_tag", Text),
                Field::StorageClass => ("storage_class", Text),
                Field::IsMultipartUploaded => ("is_multipart_uploaded", Boolean),
                Field::ReplicationStatus => ("replication_status", Text),
                Field::EncryptionStatus => ("encryption_status", Text),
                Field::ObjectLockRetainUntilDate => ("object_lock_retain_until_date", Timestamp),
                Field::ObjectLockMode => ("object_lock_mode", Text),
                Field::ObjectLockLegalHoldStatus => ("object_lock_legal_hold_status", Text),
                Field::IntelligentTieringAccessTier => ("intelligent_tiering_access_tier", Text),
                Field::BucketKeyStatus => ("bucket_key_status", Text),
                Field::ChecksumAlgorithm => ("checksum_algorithm", Text),
                Field::ObjectAccessControlList => ("object_access_control_list", Text),
                Field::ObjectOwner => ("object_owner", Text),
                Field::ObjectLockEventHoldStatus => ("object_lock_event_hold_status", Text),
                Field::ObjectLockEventHoldDuration => ("object_lock_event_hold_duration", Int32),
                Field::LifecycleExpirationDate => ("lifecycle_expiration_date", Timestamp),
            },
        };
        parquet::Column { name, ty, required: matches!(self, Column::Bucket | Column::Key) }
    }
}

impl Destination {
    fn parse(node: Node) -> Result<Destination, Invalid> {
        only(node, &["AccountId", "Bucket", "Encryption", "Format", "Prefix"])?;
        let format = match required(node, "Format")?.as_str() {
            "CSV" => Format::Csv,
            "Parquet" => Format::Parquet,
            "ORC" => {
                return Err(Invalid::Unsupported(
                    "Inventory reports in ORC are not implemented; CSV and Parquet are".to_owned(),
                ));
            }
            _ => return Err(Invalid::Malformed("Format is CSV, ORC or Parquet".to_owned())),
        };
        let arn = required(node, "Bucket")?;
        let bucket = arn
            .strip_prefix("arn:aws:s3:::")
            .filter(|name| crate::s3::buckets::create::valid_bucket_name(name))
            .ok_or_else(|| Invalid::Argument(format!("The destination bucket {arn} is not a valid bucket ARN")))?;
        let account = text(node, "AccountId")?;
        if account.as_deref().is_some_and(|a| a.len() != 12 || !a.bytes().all(|b| b.is_ascii_digit())) {
            return Err(Invalid::Argument("The destination's AccountId is not a valid account ID".to_owned()));
        }
        let encryption = match child(node, "Encryption")? {
            None => None,
            Some(encryption) => {
                only(encryption, &["SSE-S3", "SSE-KMS"])?;
                match (child(encryption, "SSE-S3")?, child(encryption, "SSE-KMS")?) {
                    (Some(_), None) => Some(Encryption::S3),
                    (None, Some(kms)) => {
                        only(kms, &["KeyId"])?;
                        let key = required(kms, "KeyId")?;
                        let id = key.strip_prefix("arn:aws:kms:").unwrap_or(&key);
                        let id = crate::kms::KeyId::parse(id)
                            .ok_or_else(|| Invalid::Argument(format!("The KMS key ID {key} is not valid")))?;
                        Some(Encryption::Kms(id.as_string()))
                    }
                    _ => return Err(Invalid::Malformed("Encryption is either SSE-S3 or SSE-KMS".to_owned())),
                }
            }
        };
        Ok(Destination {
            account,
            bucket: bucket.to_owned(),
            prefix: text(node, "Prefix")?.filter(|p| !p.is_empty()),
            encryption,
            format,
        })
    }

    fn to_xml(&self) -> String {
        let mut xml = String::from("<Destination><S3BucketDestination>");
        if let Some(account) = &self.account {
            xml.push_str(&format!("<AccountId>{}</AccountId>", xml_escape(account)));
        }
        xml.push_str(&format!("<Bucket>arn:aws:s3:::{}</Bucket>", xml_escape(&self.bucket)));
        match &self.encryption {
            None => {}
            Some(Encryption::S3) => xml.push_str("<Encryption><SSE-S3/></Encryption>"),
            Some(Encryption::Kms(key)) => xml.push_str(&format!(
                "<Encryption><SSE-KMS><KeyId>arn:aws:kms:{}</KeyId></SSE-KMS></Encryption>",
                xml_escape(key)
            )),
        }
        xml.push_str(&format!("<Format>{}</Format>", self.format.name()));
        if let Some(prefix) = &self.prefix {
            xml.push_str(&format!("<Prefix>{}</Prefix>", xml_escape(prefix)));
        }
        xml.push_str("</S3BucketDestination></Destination>");
        xml
    }

    /// The destination bucket's ARN.
    pub fn arn(&self) -> String {
        format!("arn:aws:s3:::{}", self.bucket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(inner: &str) -> String {
        format!("<InventoryConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{inner}</InventoryConfiguration>")
    }

    const DESTINATION: &str = "<Destination><S3BucketDestination><Bucket>arn:aws:s3:::reports</Bucket>\
        <Format>CSV</Format></S3BucketDestination></Destination>";

    fn minimal(extra: &str) -> String {
        config(&format!(
            "{DESTINATION}<IsEnabled>true</IsEnabled><Id>daily</Id>\
             <IncludedObjectVersions>Current</IncludedObjectVersions>\
             <Schedule><Frequency>Daily</Frequency></Schedule>{extra}"
        ))
    }

    #[test]
    fn parses_a_full_configuration() {
        let body = config(
            "<Destination><S3BucketDestination><AccountId>123456789012</AccountId>\
             <Bucket>arn:aws:s3:::reports</Bucket><Encryption><SSE-S3/></Encryption>\
             <Format>CSV</Format><Prefix>inv</Prefix></S3BucketDestination></Destination>\
             <IsEnabled>false</IsEnabled><Filter><Prefix>photos/</Prefix></Filter><Id>all-1</Id>\
             <IncludedObjectVersions>All</IncludedObjectVersions>\
             <OptionalFields><Field>ETag</Field><Field>Size</Field></OptionalFields>\
             <Schedule><Frequency>Weekly</Frequency></Schedule>",
        );
        let parsed = Configuration::parse(&body).unwrap();
        assert_eq!(
            parsed,
            Configuration {
                id: "all-1".to_owned(),
                enabled: false,
                destination: Destination {
                    account: Some("123456789012".to_owned()),
                    bucket: "reports".to_owned(),
                    prefix: Some("inv".to_owned()),
                    encryption: Some(Encryption::S3),
                    format: Format::Csv,
                },
                prefix: Some("photos/".to_owned()),
                all_versions: true,
                fields: vec![Field::ETag, Field::Size],
                frequency: Frequency::Weekly,
            }
        );
        // As it's answered, and kept.
        assert_eq!(Configuration::parse(&parsed.to_xml()).unwrap(), parsed);
        assert_eq!(Configuration::from_json(&parsed.to_json()).unwrap(), parsed);
        // Columns in the report's order, not the request's.
        assert_eq!(
            parsed.columns(),
            [
                Column::Bucket,
                Column::Key,
                Column::VersionId,
                Column::IsLatest,
                Column::IsDeleteMarker,
                Column::Field(Field::Size),
                Column::Field(Field::ETag),
            ]
        );
    }

    #[test]
    fn current_objects_have_no_version_columns() {
        let parsed = Configuration::parse(&minimal("")).unwrap();
        assert_eq!(parsed.columns(), [Column::Bucket, Column::Key]);
        assert_eq!(parsed.prefix, None);
        assert_eq!(parsed.destination.encryption, None);
    }

    #[test]
    fn refuses_what_s3_refuses() {
        let malformed = |body: &str| matches!(Configuration::parse(body), Err(Invalid::Malformed(_)));
        assert!(malformed("not xml"));
        assert!(malformed(&minimal("<Unknown/>")));
        assert!(malformed(&minimal("<OptionalFields><Field>Colour</Field></OptionalFields>")));
        assert!(malformed(&minimal("<OptionalFields><Field>IntelligentTieringReferenceDate</Field></OptionalFields>")));
        assert!(malformed(&config(&format!("{DESTINATION}<IsEnabled>true</IsEnabled><Id>a</Id>"))));
        let unsupported = config(
            "<Destination><S3BucketDestination><Bucket>arn:aws:s3:::reports</Bucket>\
             <Format>ORC</Format></S3BucketDestination></Destination>\
             <IsEnabled>true</IsEnabled><Id>a</Id><IncludedObjectVersions>All</IncludedObjectVersions>\
             <Schedule><Frequency>Daily</Frequency></Schedule>",
        );
        assert!(matches!(Configuration::parse(&unsupported), Err(Invalid::Unsupported(_))));
        let not_an_arn = minimal("").replace("arn:aws:s3:::reports", "reports");
        assert!(matches!(Configuration::parse(&not_an_arn), Err(Invalid::Argument(_))));
        let bad_id = minimal("").replace("<Id>daily</Id>", "<Id>a/b</Id>");
        assert!(matches!(Configuration::parse(&bad_id), Err(Invalid::Argument(_))));
        let twice = minimal("<OptionalFields><Field>Size</Field><Field>Size</Field></OptionalFields>");
        assert!(matches!(Configuration::parse(&twice), Err(Invalid::Argument(_))));
    }

    #[test]
    fn parquet_is_a_format() {
        let parsed = Configuration::parse(&minimal("").replace("<Format>CSV</Format>", "<Format>Parquet</Format>")).unwrap();
        assert_eq!(parsed.destination.format, Format::Parquet);
        assert!(parsed.to_xml().contains("<Format>Parquet</Format>"));
        assert_eq!(Configuration::parse(&parsed.to_xml()).unwrap(), parsed);
        assert_eq!(Configuration::from_json(&parsed.to_json()).unwrap(), parsed);
        // Configurations kept before there was a format are CSV's.
        let kept = r#"{"id":"a","enabled":true,"destination":{"bucket":"reports"},"all_versions":false,"frequency":"Daily"}"#;
        assert_eq!(Configuration::from_json(kept).unwrap().destination.format, Format::Csv);
    }

    #[test]
    fn the_event_hold_duration_has_a_unit_column() {
        let parsed = Configuration::parse(&minimal(
            "<OptionalFields><Field>ObjectLockEventHoldDuration</Field></OptionalFields>",
        ))
        .unwrap();
        assert_eq!(
            parsed.columns(),
            [
                Column::Bucket,
                Column::Key,
                Column::Field(Field::ObjectLockEventHoldDuration),
                Column::EventHoldDurationUnit,
            ]
        );
    }
}
