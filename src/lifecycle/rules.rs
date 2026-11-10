//! A bucket's lifecycle configuration: its rules, as S3's
//! `<LifecycleConfiguration>` writes them, how they're stored (JSON, in
//! `buckets.lifecycle`), and what they make due.
//!
//! Each rule picks objects by a filter (a key prefix, and bounds on their
//! size), and says what happens to them, and when:
//!
//! - `Expiration`: the current version expires a number of days after it was
//!   written, or from a date on. Or, with `ExpiredObjectDeleteMarker`, a
//!   delete marker that's a key's only version is removed.
//! - `NoncurrentVersionExpiration`: a noncurrent version is removed for good
//!   a number of days after it became noncurrent (a newer version was
//!   written, or a delete marker), keeping the newest few if asked.
//! - `AbortIncompleteMultipartUpload`: an upload is aborted a number of days
//!   after it was created.
//!
//! As in S3, a number of days counts from the version's time to the next
//! midnight UTC after that many days: an object written at 10:30 on the 1st,
//! under a rule of 1 day, expires at midnight starting the 3rd.
//!
//! Not supported, and refused when asked for: transitions to other storage
//! classes (Cairn has one), and filters on tags (Cairn doesn't keep them).
//! Both would be more fields here, and more kinds of `Due`; the stored JSON
//! refuses fields it doesn't know (`deny_unknown_fields`), so that a node too
//! old to know a newer rule's field skips the bucket instead of applying the
//! rule without it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::s3::util::xml_escape;

/// The most rules a configuration may have, as in S3.
const MAX_RULES: usize = 1000;
/// The longest rule ID, as in S3.
const MAX_ID_LENGTH: usize = 255;
/// The most noncurrent versions a rule may keep, as in S3.
const MAX_NEWER_NONCURRENT: u32 = 100;

/// A bucket's lifecycle configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    /// `Status`: a disabled rule is kept, but does nothing.
    pub enabled: bool,
    pub filter: Filter,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration: Option<Expiration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noncurrent_expiration: Option<NoncurrentExpiration>,
    /// `AbortIncompleteMultipartUpload`'s `DaysAfterInitiation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abort_upload_days: Option<u32>,
}

/// Which objects a rule applies to: those with keys starting with `prefix`,
/// and sizes strictly between the bounds. All of them, by default.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_greater_than: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_less_than: Option<i64>,
}

/// `Expiration`: one of `days` and `date`, or `expired_object_delete_marker`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expiration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date: Option<Day>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expired_object_delete_marker: bool,
}

/// `NoncurrentVersionExpiration`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoncurrentExpiration {
    pub days: u32,
    /// How many of the newest noncurrent versions are kept regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub newer_versions: Option<u32>,
}

/// A day, UTC, as the number of days since 1970-01-01.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Day(pub i64);

const SECS_PER_DAY: i64 = 24 * 3600;

impl Day {
    /// The day `time` falls on.
    pub fn of(time: SystemTime) -> Day {
        Day(seconds(time).div_euclid(SECS_PER_DAY))
    }

    /// The midnight it starts with.
    pub fn midnight(self) -> SystemTime {
        let secs = self.0 * SECS_PER_DAY;
        match u64::try_from(secs) {
            Ok(secs) => UNIX_EPOCH + Duration::from_secs(secs),
            Err(_) => UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs()),
        }
    }

    /// The latest time something may have happened, for `days` to have
    /// passed since by midnight starting today: `days` before it.
    fn cutoff(self, days: u32) -> SystemTime {
        Day(self.0 - i64::from(days)).midnight()
    }

    /// Its date, as (year, month, day). Howard Hinnant's `civil_from_days`.
    fn civil(self) -> (i64, u32, u32) {
        let z = self.0 + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        (year, month, day)
    }

    /// The day of a date, if it is one. Howard Hinnant's `days_from_civil`.
    fn from_civil(year: i64, month: u32, day: u32) -> Option<Day> {
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
            2 => 28,
            _ => return None,
        };
        if day == 0 || day > days_in_month {
            return None;
        }
        let year = year - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let yoe = year.rem_euclid(400);
        let mp = i64::from((month + 9) % 12);
        let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        Some(Day(era * 146_097 + doe - 719_468))
    }

    /// A `Date` of a rule: midnight UTC in ISO 8601, as S3 requires it
    /// (`2026-01-01T00:00:00Z`, or with fractional seconds, or `+00:00`).
    /// `Err` with why if it isn't one, or isn't at midnight.
    fn parse(text: &str) -> Result<Day, Invalid> {
        let malformed = || Invalid::Malformed("Date must be in ISO 8601 format".to_owned());
        let (date, time) = text.split_once('T').ok_or_else(malformed)?;
        let mut fields = date.splitn(3, '-');
        let mut field = |len| {
            fields
                .next()
                .filter(|f: &&str| f.len() == len && f.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|f| f.parse::<u32>().ok())
                .ok_or_else(malformed)
        };
        let (year, month, day) = (field(4)?, field(2)?, field(2)?);
        let day = Day::from_civil(i64::from(year), month, day).ok_or_else(malformed)?;
        let time = time
            .strip_suffix('Z')
            .or_else(|| time.strip_suffix("+00:00"))
            .ok_or_else(malformed)?;
        let (clock, fraction) = time.split_once('.').unwrap_or((time, "0"));
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        let parts: Vec<&str> = clock.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|p| p.len() != 2 || !digits(p)) || !digits(fraction) {
            return Err(malformed());
        }
        if parts.iter().any(|p| *p != "00") || fraction.bytes().any(|b| b != b'0') {
            return Err(Invalid::Argument("'Date' must be at midnight GMT".to_owned()));
        }
        Ok(day)
    }

    /// As S3 writes a rule's `Date`.
    fn to_iso(self) -> String {
        let (year, month, day) = self.civil();
        format!("{year:04}-{month:02}-{day:02}T00:00:00.000Z")
    }
}

/// Seconds since the epoch, negative before it.
fn seconds(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
    }
}

/// Why a configuration was refused, as S3 refuses it.
#[derive(Debug, PartialEq)]
pub enum Invalid {
    /// 400 MalformedXML: not the document S3 expects.
    Malformed(String),
    /// 400 InvalidArgument: the document, with a value S3 doesn't allow.
    Argument(String),
    /// 501 NotImplemented: something S3 has and Cairn doesn't.
    Unsupported(String),
}

type Node<'a, 'i> = roxmltree::Node<'a, 'i>;

/// The element children of `node` named `name`.
fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    node.children().filter(|n| n.tag_name().name() == name).collect()
}

/// The text of `node`'s only child `name`, if it has one; `Err` if it has
/// several.
fn text(node: Node, name: &str) -> Result<Option<String>, Invalid> {
    match children(node, name)[..] {
        [] => Ok(None),
        [child] => Ok(Some(child.text().unwrap_or("").trim().to_owned())),
        _ => Err(Invalid::Malformed(format!("more than one {name}"))),
    }
}

/// The number in `node`'s child `name`, if it has one: at least `min`.
fn number<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    node: Node,
    name: &str,
    min: T,
) -> Result<Option<T>, Invalid> {
    let Some(text) = text(node, name)? else { return Ok(None) };
    match text.parse::<T>() {
        Ok(n) if n >= min => Ok(Some(n)),
        Ok(_) => Err(Invalid::Argument(format!("{name} must be at least {min}"))),
        Err(_) => Err(Invalid::Malformed(format!("{name} must be a number"))),
    }
}

/// Refuses the children of `node` that aren't among `known`: S3's schema has
/// no others, and one Cairn doesn't know may well change what a rule does.
fn only(node: Node, known: &[&str]) -> Result<(), Invalid> {
    match node.children().filter(|n| n.is_element()).find(|n| !known.contains(&n.tag_name().name())) {
        Some(n) => Err(Invalid::Malformed(format!("unknown element {}", n.tag_name().name()))),
        None => Ok(()),
    }
}

fn tags_unsupported() -> Invalid {
    Invalid::Unsupported("lifecycle rules can't filter on tags: Cairn doesn't keep object tags".to_owned())
}

impl Configuration {
    /// Parses a `<LifecycleConfiguration>`, as PutBucketLifecycleConfiguration
    /// takes it. A rule without an ID is given one.
    pub fn parse(body: &str) -> Result<Configuration, Invalid> {
        let doc = roxmltree::Document::parse(body).map_err(|_| Invalid::Malformed("not XML".to_owned()))?;
        let root = doc.root_element();
        if root.tag_name().name() != "LifecycleConfiguration" {
            return Err(Invalid::Malformed("not a LifecycleConfiguration".to_owned()));
        }
        only(root, &["Rule"])?;
        let rules = children(root, "Rule");
        if rules.is_empty() {
            return Err(Invalid::Malformed("a lifecycle configuration needs at least one rule".to_owned()));
        }
        if rules.len() > MAX_RULES {
            return Err(Invalid::Argument(format!("a lifecycle configuration has at most {MAX_RULES} rules")));
        }
        let rules = rules.into_iter().map(Rule::parse).collect::<Result<Vec<_>, _>>()?;
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(Invalid::Argument("Rule ID must be unique. Found same ID for more than one rule".to_owned()));
        }
        Ok(Configuration { rules })
    }

    /// As GetBucketLifecycleConfiguration answers.
    pub fn to_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        for rule in &self.rules {
            rule.write_xml(&mut out);
        }
        out.push_str("</LifecycleConfiguration>");
        out
    }

    /// As it's stored.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a configuration serializes")
    }

    pub fn from_json(json: &str) -> serde_json::Result<Configuration> {
        serde_json::from_str(json)
    }

    fn enabled(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// Whether any rule expires objects or versions (rather than only
    /// aborting uploads).
    pub fn expires_objects(&self) -> bool {
        self.enabled().any(|r| r.expiration.is_some() || r.noncurrent_expiration.is_some())
    }

    /// Whether any rule aborts uploads.
    pub fn aborts_uploads(&self) -> bool {
        self.enabled().any(|r| r.abort_upload_days.is_some())
    }

    /// What's due among the versions of `key` (all of them, newest first),
    /// as of `today`.
    pub fn due(&self, key: &str, versions: &[Version], today: Day) -> Vec<Due> {
        let mut due = Vec::new();
        let Some((newest, older)) = versions.split_first() else { return due };
        if newest.is_latest {
            let rules = || self.enabled().filter(|r| r.filter.matches(key, newest));
            let expired = if newest.delete_marker {
                // Only a delete marker that hides nothing: removing it
                // changes nothing that can be read or listed, but a listing
                // of versions.
                older.is_empty()
                    && rules().any(|r| r.expiration.as_ref().is_some_and(|e| e.expired_object_delete_marker))
            } else {
                rules().any(|r| r.expiration.as_ref().is_some_and(|e| e.expires(newest.last_modified, today)))
            };
            if expired {
                let kind = if newest.delete_marker { Kind::Marker } else { Kind::Current };
                due.push(Due { version: newest.clone(), kind });
            }
        }
        // A version became noncurrent when the next one was written.
        for (i, version) in versions.iter().enumerate().skip(1) {
            let successor = &versions[i - 1];
            // Newer noncurrent versions: all newer ones, but the current.
            let newer = i - 1;
            let expired = self.enabled().filter(|r| r.filter.matches(key, version)).any(|r| {
                r.noncurrent_expiration.as_ref().is_some_and(|n| {
                    successor.last_modified <= today.cutoff(n.days)
                        && newer >= n.newer_versions.unwrap_or(0) as usize
                })
            });
            if expired {
                let kind = Kind::Noncurrent { successor: successor.id, newer: i as i32 };
                due.push(Due { version: version.clone(), kind });
            }
        }
        due
    }

    /// Whether the upload of `key` created at `initiated` is due to be
    /// aborted, as of `today`.
    pub fn aborts(&self, key: &str, initiated: SystemTime, today: Day) -> bool {
        self.enabled().any(|r| {
            key.starts_with(&r.filter.prefix) && r.abort_upload_days.is_some_and(|days| initiated <= today.cutoff(days))
        })
    }
}

impl Rule {
    fn parse(node: Node) -> Result<Rule, Invalid> {
        only(
            node,
            &[
                "ID",
                "Prefix",
                "Filter",
                "Status",
                "Expiration",
                "NoncurrentVersionExpiration",
                "AbortIncompleteMultipartUpload",
                "Transition",
                "NoncurrentVersionTransition",
            ],
        )?;
        if !children(node, "Transition").is_empty() || !children(node, "NoncurrentVersionTransition").is_empty() {
            return Err(Invalid::Unsupported(
                "lifecycle transitions aren't supported: Cairn has a single storage class".to_owned(),
            ));
        }
        let id = match text(node, "ID")? {
            Some(id) if id.len() > MAX_ID_LENGTH => {
                return Err(Invalid::Argument(format!("ID length should not exceed allowed limit of {MAX_ID_LENGTH}")));
            }
            Some(id) if !id.is_empty() => id,
            _ => uuid::Uuid::new_v4().simple().to_string(),
        };
        let enabled = match text(node, "Status")?.as_deref() {
            Some("Enabled") => true,
            Some("Disabled") => false,
            _ => return Err(Invalid::Malformed("Status must be Enabled or Disabled".to_owned())),
        };
        // The filter: S3's `Filter`, or the older `Prefix` in its place.
        let filter = match (text(node, "Prefix")?, &children(node, "Filter")[..]) {
            (Some(prefix), []) => Filter { prefix, ..Filter::default() },
            (None, [filter]) => Filter::parse(*filter)?,
            (None, []) => return Err(Invalid::Malformed("a rule needs a Filter or a Prefix".to_owned())),
            _ => return Err(Invalid::Malformed("a rule has either a Filter or a Prefix, once".to_owned())),
        };
        let expiration = match &children(node, "Expiration")[..] {
            [] => None,
            [expiration] => Some(Expiration::parse(*expiration)?),
            _ => return Err(Invalid::Malformed("more than one Expiration".to_owned())),
        };
        let noncurrent_expiration = match &children(node, "NoncurrentVersionExpiration")[..] {
            [] => None,
            [noncurrent] => {
                only(*noncurrent, &["NoncurrentDays", "NewerNoncurrentVersions"])?;
                let days = number(*noncurrent, "NoncurrentDays", 1u32)?
                    .ok_or_else(|| Invalid::Malformed("NoncurrentVersionExpiration needs NoncurrentDays".to_owned()))?;
                let newer_versions = number(*noncurrent, "NewerNoncurrentVersions", 1u32)?;
                if newer_versions.is_some_and(|n| n > MAX_NEWER_NONCURRENT) {
                    return Err(Invalid::Argument(format!(
                        "NewerNoncurrentVersions must be at most {MAX_NEWER_NONCURRENT}"
                    )));
                }
                Some(NoncurrentExpiration { days, newer_versions })
            }
            _ => return Err(Invalid::Malformed("more than one NoncurrentVersionExpiration".to_owned())),
        };
        let abort_upload_days = match &children(node, "AbortIncompleteMultipartUpload")[..] {
            [] => None,
            [abort] => {
                only(*abort, &["DaysAfterInitiation"])?;
                Some(number(*abort, "DaysAfterInitiation", 1u32)?.ok_or_else(|| {
                    Invalid::Malformed("AbortIncompleteMultipartUpload needs DaysAfterInitiation".to_owned())
                })?)
            }
            _ => return Err(Invalid::Malformed("more than one AbortIncompleteMultipartUpload".to_owned())),
        };
        if abort_upload_days.is_some() && (filter.size_greater_than.is_some() || filter.size_less_than.is_some()) {
            // An upload has no size yet.
            return Err(Invalid::Argument(
                "AbortIncompleteMultipartUpload can't be used with an object size filter".to_owned(),
            ));
        }
        if expiration.is_none() && noncurrent_expiration.is_none() && abort_upload_days.is_none() {
            return Err(Invalid::Argument("At least one action needs to be specified in a rule".to_owned()));
        }
        Ok(Rule { id, enabled, filter, expiration, noncurrent_expiration, abort_upload_days })
    }

    fn write_xml(&self, out: &mut String) {
        out.push_str(&format!("<Rule><ID>{}</ID>", xml_escape(&self.id)));
        self.filter.write_xml(out);
        out.push_str(if self.enabled { "<Status>Enabled</Status>" } else { "<Status>Disabled</Status>" });
        if let Some(e) = &self.expiration {
            out.push_str("<Expiration>");
            if let Some(days) = e.days {
                out.push_str(&format!("<Days>{days}</Days>"));
            }
            if let Some(date) = e.date {
                out.push_str(&format!("<Date>{}</Date>", date.to_iso()));
            }
            if e.expired_object_delete_marker {
                out.push_str("<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>");
            }
            out.push_str("</Expiration>");
        }
        if let Some(n) = &self.noncurrent_expiration {
            out.push_str(&format!("<NoncurrentVersionExpiration><NoncurrentDays>{}</NoncurrentDays>", n.days));
            if let Some(newer) = n.newer_versions {
                out.push_str(&format!("<NewerNoncurrentVersions>{newer}</NewerNoncurrentVersions>"));
            }
            out.push_str("</NoncurrentVersionExpiration>");
        }
        if let Some(days) = self.abort_upload_days {
            out.push_str(&format!(
                "<AbortIncompleteMultipartUpload><DaysAfterInitiation>{days}</DaysAfterInitiation>\
                 </AbortIncompleteMultipartUpload>"
            ));
        }
        out.push_str("</Rule>");
    }
}

impl Filter {
    /// A `<Filter>`: empty, or one condition, or several under `<And>`.
    fn parse(node: Node) -> Result<Filter, Invalid> {
        const CONDITIONS: &[&str] = &["Prefix", "Tag", "ObjectSizeGreaterThan", "ObjectSizeLessThan"];
        let mut known = CONDITIONS.to_vec();
        known.push("And");
        only(node, &known)?;
        let conditions = node.children().filter(|n| n.is_element()).count();
        let source = match &children(node, "And")[..] {
            [] if conditions <= 1 => node,
            [and] if conditions == 1 => {
                only(*and, CONDITIONS)?;
                *and
            }
            _ => return Err(Invalid::Malformed("a Filter has one condition, or several under And".to_owned())),
        };
        if !children(source, "Tag").is_empty() {
            return Err(tags_unsupported());
        }
        let filter = Filter {
            prefix: text(source, "Prefix")?.unwrap_or_default(),
            size_greater_than: number(source, "ObjectSizeGreaterThan", 0i64)?,
            size_less_than: number(source, "ObjectSizeLessThan", 1i64)?,
        };
        if let (Some(greater), Some(less)) = (filter.size_greater_than, filter.size_less_than)
            && greater >= less
        {
            return Err(Invalid::Argument("ObjectSizeGreaterThan must be less than ObjectSizeLessThan".to_owned()));
        }
        Ok(filter)
    }

    fn write_xml(&self, out: &mut String) {
        let mut conditions = Vec::new();
        if !self.prefix.is_empty() {
            conditions.push(format!("<Prefix>{}</Prefix>", xml_escape(&self.prefix)));
        }
        if let Some(n) = self.size_greater_than {
            conditions.push(format!("<ObjectSizeGreaterThan>{n}</ObjectSizeGreaterThan>"));
        }
        if let Some(n) = self.size_less_than {
            conditions.push(format!("<ObjectSizeLessThan>{n}</ObjectSizeLessThan>"));
        }
        match conditions.len() {
            0 => out.push_str("<Filter></Filter>"),
            1 => out.push_str(&format!("<Filter>{}</Filter>", conditions[0])),
            _ => out.push_str(&format!("<Filter><And>{}</And></Filter>", conditions.concat())),
        }
    }

    /// Whether `version` of `key` passes it. A delete marker has no size, so
    /// only its key counts.
    fn matches(&self, key: &str, version: &Version) -> bool {
        key.starts_with(&self.prefix)
            && (version.delete_marker
                || (self.size_greater_than.is_none_or(|n| version.size > n)
                    && self.size_less_than.is_none_or(|n| version.size < n)))
    }
}

impl Expiration {
    fn parse(node: Node) -> Result<Expiration, Invalid> {
        only(node, &["Days", "Date", "ExpiredObjectDeleteMarker"])?;
        let expiration = Expiration {
            days: number(node, "Days", 1u32)?,
            date: text(node, "Date")?.as_deref().map(Day::parse).transpose()?,
            expired_object_delete_marker: match text(node, "ExpiredObjectDeleteMarker")?.as_deref() {
                None | Some("false") => false,
                Some("true") => true,
                Some(_) => {
                    return Err(Invalid::Malformed("ExpiredObjectDeleteMarker must be true or false".to_owned()));
                }
            },
        };
        match expiration {
            Expiration { days: Some(_), date: Some(_), .. } => {
                Err(Invalid::Malformed("an Expiration has either Days or a Date".to_owned()))
            }
            Expiration { days: None, date: None, expired_object_delete_marker: false } => {
                // `ExpiredObjectDeleteMarker` false alone does nothing, which
                // S3 allows, but not an empty Expiration.
                if text(node, "ExpiredObjectDeleteMarker")?.is_some() {
                    Ok(expiration)
                } else {
                    Err(Invalid::Malformed("an Expiration needs Days, a Date or ExpiredObjectDeleteMarker".to_owned()))
                }
            }
            Expiration { expired_object_delete_marker: true, days, date } if days.is_some() || date.is_some() => {
                Err(Invalid::Argument(
                    "ExpiredObjectDeleteMarker cannot be specified with Days or Date in a Lifecycle Expiration Policy"
                        .to_owned(),
                ))
            }
            expiration => Ok(expiration),
        }
    }

    /// Whether a current version written at `written` has expired by `today`.
    fn expires(&self, written: SystemTime, today: Day) -> bool {
        self.days.is_some_and(|days| written <= today.cutoff(days)) || self.date.is_some_and(|date| today >= date)
    }
}

/// A version of a key, as a lifecycle run reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct Version {
    /// Its row id, which grows with the order versions were written in.
    pub id: i64,
    pub version_id: String,
    pub is_latest: bool,
    pub delete_marker: bool,
    pub size: i64,
    pub last_modified: SystemTime,
}

/// A version that a rule made due, and what made it so, as
/// `cairn_lifecycle_expire` checks it again.
#[derive(Clone, Debug, PartialEq)]
pub struct Due {
    pub version: Version,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    /// The current version expires (a delete, as DeleteObject's).
    Current,
    /// A delete marker, the key's only version, is removed.
    Marker,
    /// A noncurrent version is removed: the version after it is
    /// `successor`, and there are `newer` versions newer than it.
    Noncurrent { successor: i64, newer: i32 },
}

impl Kind {
    pub fn as_db(self) -> &'static str {
        match self {
            Kind::Current => "current",
            Kind::Marker => "marker",
            Kind::Noncurrent { .. } => "noncurrent",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(rules: &str) -> String {
        format!("<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">{rules}</LifecycleConfiguration>")
    }

    fn parse(rules: &str) -> Result<Configuration, Invalid> {
        Configuration::parse(&config(rules))
    }

    fn day(y: i64, m: u32, d: u32) -> Day {
        Day::from_civil(y, m, d).unwrap()
    }

    fn at(day: Day, hours: u64) -> SystemTime {
        day.midnight() + Duration::from_secs(hours * 3600)
    }

    #[test]
    fn days_are_dates() {
        assert_eq!(Day::from_civil(1970, 1, 1), Some(Day(0)));
        assert_eq!(Day::from_civil(2000, 3, 1), Some(Day(11_017)));
        assert_eq!(Day::from_civil(2024, 2, 29).map(Day::civil), Some((2024, 2, 29)));
        assert_eq!(Day::from_civil(2023, 2, 29), None);
        assert_eq!(Day::from_civil(1900, 2, 29), None);
        assert_eq!(Day(-1).civil(), (1969, 12, 31));
        for n in -1000..100_000 {
            let (y, m, d) = Day(n).civil();
            assert_eq!(Day::from_civil(y, m, d), Some(Day(n)));
        }
        assert_eq!(Day::of(at(day(2026, 11, 10), 23)), day(2026, 11, 10));
        assert_eq!(Day::of(UNIX_EPOCH - Duration::from_secs(1)), Day(-1));
        assert_eq!(day(2026, 1, 1).to_iso(), "2026-01-01T00:00:00.000Z");
    }

    #[test]
    fn dates_are_midnights() {
        for ok in ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00+00:00"] {
            assert_eq!(Day::parse(ok), Ok(day(2026, 1, 1)), "{ok}");
        }
        for bad in ["2026-01-01", "2026-1-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-01-01T00:00:00", "x"] {
            assert!(matches!(Day::parse(bad), Err(Invalid::Malformed(_))), "{bad}");
        }
        assert!(matches!(Day::parse("2026-01-01T12:00:00Z"), Err(Invalid::Argument(_))));
        assert!(matches!(Day::parse("2026-01-01T00:00:00.5Z"), Err(Invalid::Argument(_))));
    }

    #[test]
    fn parses_and_writes_configurations() {
        let rules = "<Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
                     <Expiration><Days>30</Days></Expiration></Rule>\
                     <Rule><ID>old</ID><Filter><And><Prefix>a&amp;b</Prefix><ObjectSizeGreaterThan>10\
                     </ObjectSizeGreaterThan><ObjectSizeLessThan>20</ObjectSizeLessThan></And></Filter>\
                     <Status>Disabled</Status><NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays>\
                     <NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>\
                     <Rule><ID>all</ID><Filter></Filter><Status>Enabled</Status>\
                     <Expiration><Date>2027-01-01T00:00:00.000Z</Date></Expiration>\
                     <AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation>\
                     </AbortIncompleteMultipartUpload></Rule>\
                     <Rule><ID>markers</ID><Prefix>m/</Prefix><Status>Enabled</Status>\
                     <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>";
        let parsed = parse(rules).unwrap();
        assert_eq!(
            parsed.rules[0],
            Rule {
                id: "logs".to_owned(),
                enabled: true,
                filter: Filter { prefix: "logs/".to_owned(), ..Filter::default() },
                expiration: Some(Expiration { days: Some(30), ..Expiration::default() }),
                noncurrent_expiration: None,
                abort_upload_days: None,
            }
        );
        assert_eq!(
            parsed.rules[1].filter,
            Filter { prefix: "a&b".to_owned(), size_greater_than: Some(10), size_less_than: Some(20) }
        );
        assert_eq!(parsed.rules[1].noncurrent_expiration, Some(NoncurrentExpiration { days: 7, newer_versions: Some(3) }));
        assert_eq!(parsed.rules[2].expiration.as_ref().unwrap().date, Some(day(2027, 1, 1)));
        assert_eq!(parsed.rules[2].abort_upload_days, Some(2));
        assert!(parsed.rules[3].expiration.as_ref().unwrap().expired_object_delete_marker);
        // What it writes back parses to the same, and so does what it stores.
        assert_eq!(Configuration::parse(&parsed.to_xml()), Ok(parsed.clone()));
        assert_eq!(Configuration::from_json(&parsed.to_json()).unwrap(), parsed);
        // A rule without an ID gets one.
        let unnamed = parse("<Rule><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>");
        assert_eq!(unnamed.unwrap().rules[0].id.len(), 32);
    }

    #[test]
    fn refuses_bad_configurations() {
        let rule = |body: &str| format!("<Rule><ID>r</ID>{body}</Rule>");
        let expire = "<Expiration><Days>1</Days></Expiration>";
        let malformed = [
            "not xml".to_owned(),
            "<Other/>".to_owned(),
            config(""),
            config(&rule(&format!("<Status>Enabled</Status>{expire}"))),
            config(&rule(&format!("<Filter/><Status>On</Status>{expire}"))),
            config(&rule(&format!("<Filter/><Prefix/><Status>Enabled</Status>{expire}"))),
            config(&rule("<Filter/><Status>Enabled</Status><Expiration/>")),
            config(&rule(
                "<Filter/><Status>Enabled</Status><Expiration><Days>1</Days>\
                 <Date>2026-01-01T00:00:00Z</Date></Expiration>",
            )),
            config(&rule(&format!(
                "<Filter><Prefix>a</Prefix><ObjectSizeLessThan>5</ObjectSizeLessThan></Filter>\
                 <Status>Enabled</Status>{expire}"
            ))),
            config(&rule(&format!("<Filter/><Status>Enabled</Status><Bogus/>{expire}"))),
            config(&rule("<Filter/><Status>Enabled</Status><Expiration><Days>x</Days></Expiration>")),
            config(&rule(
                "<Filter/><Status>Enabled</Status><NoncurrentVersionExpiration>\
                 <NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration>",
            )),
        ];
        for bad in malformed {
            assert!(matches!(Configuration::parse(&bad), Err(Invalid::Malformed(_))), "{bad}");
        }
        let invalid = [
            rule("<Filter/><Status>Enabled</Status>"),
            rule("<Filter/><Status>Enabled</Status><Expiration><Days>0</Days></Expiration>"),
            rule(
                "<Filter/><Status>Enabled</Status><Expiration><Days>1</Days>\
                 <ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>",
            ),
            rule("<Filter/><Status>Enabled</Status><Expiration><Date>2026-01-01T01:00:00Z</Date></Expiration>"),
            rule(&format!(
                "<Filter><And><ObjectSizeGreaterThan>5</ObjectSizeGreaterThan>\
                 <ObjectSizeLessThan>5</ObjectSizeLessThan></And></Filter><Status>Enabled</Status>{expire}"
            )),
            rule(
                "<Filter><ObjectSizeGreaterThan>5</ObjectSizeGreaterThan></Filter><Status>Enabled</Status>\
                 <AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation>\
                 </AbortIncompleteMultipartUpload>",
            ),
            rule(
                "<Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays>\
                 <NewerNoncurrentVersions>101</NewerNoncurrentVersions></NoncurrentVersionExpiration>",
            ),
            format!("{}{}", rule(&format!("<Filter/><Status>Enabled</Status>{expire}")), rule(&format!("<Filter/><Status>Enabled</Status>{expire}"))),
            format!("<Rule><ID>{}</ID><Filter/><Status>Enabled</Status>{expire}</Rule>", "x".repeat(256)),
        ];
        for bad in invalid {
            assert!(matches!(parse(&bad), Err(Invalid::Argument(_))), "{bad}");
        }
        let unsupported = [
            rule(&format!("<Filter><Tag><Key>a</Key><Value>b</Value></Tag></Filter><Status>Enabled</Status>{expire}")),
            rule(&format!(
                "<Filter><And><Prefix>a</Prefix><Tag><Key>a</Key><Value>b</Value></Tag></And></Filter>\
                 <Status>Enabled</Status>{expire}"
            )),
            rule(
                "<Filter/><Status>Enabled</Status><Transition><Days>1</Days>\
                 <StorageClass>GLACIER</StorageClass></Transition>",
            ),
        ];
        for bad in unsupported {
            assert!(matches!(parse(&bad), Err(Invalid::Unsupported(_))), "{bad}");
        }
    }

    #[test]
    fn stored_configurations_refuse_unknown_fields() {
        let json = r#"{"rules":[{"id":"a","enabled":true,"filter":{"tags":[["k","v"]]},"expiration":{"days":1}}]}"#;
        assert!(Configuration::from_json(json).is_err());
    }

    fn version(id: i64, written: SystemTime, latest: bool, marker: bool, size: i64) -> Version {
        Version { id, version_id: format!("v{id}"), is_latest: latest, delete_marker: marker, size, last_modified: written }
    }

    fn kinds(due: &[Due]) -> Vec<(i64, Kind)> {
        due.iter().map(|d| (d.version.id, d.kind)).collect()
    }

    #[test]
    fn current_versions_expire_at_the_midnight_after_their_days() {
        let rules = parse(
            "<Rule><ID>r</ID><Filter><And><Prefix>logs/</Prefix><ObjectSizeLessThan>100</ObjectSizeLessThan>\
             </And></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>",
        )
        .unwrap();
        let first = day(2026, 1, 1);
        let object = [version(1, at(first, 10), true, false, 10)];
        // Written at 10:00 on the 1st: one day later is 10:00 on the 2nd, so
        // it expires at midnight starting the 3rd.
        assert_eq!(rules.due("logs/a", &object, Day(first.0 + 1)), vec![]);
        assert_eq!(kinds(&rules.due("logs/a", &object, Day(first.0 + 2))), vec![(1, Kind::Current)]);
        // Not another prefix's, nor a larger object.
        assert_eq!(rules.due("other/a", &object, Day(first.0 + 2)), vec![]);
        let large = [version(1, at(first, 10), true, false, 100)];
        assert_eq!(rules.due("logs/a", &large, Day(first.0 + 2)), vec![]);
        // A disabled rule does nothing.
        let mut disabled = rules.clone();
        disabled.rules[0].enabled = false;
        assert_eq!(disabled.due("logs/a", &object, Day(first.0 + 2)), vec![]);
        // A current delete marker doesn't expire again.
        let hidden = [version(2, at(first, 10), true, true, 0), version(1, at(first, 9), false, false, 10)];
        assert_eq!(rules.due("logs/a", &hidden, Day(first.0 + 2)), vec![]);
    }

    #[test]
    fn dates_expire_everything_from_then_on() {
        let rules = parse(
            "<Rule><ID>r</ID><Filter/><Status>Enabled</Status>\
             <Expiration><Date>2026-06-01T00:00:00Z</Date></Expiration></Rule>",
        )
        .unwrap();
        let date = day(2026, 6, 1);
        let object = [version(1, at(date, 5), true, false, 1)];
        assert_eq!(rules.due("a", &object, Day(date.0 - 1)), vec![]);
        assert_eq!(kinds(&rules.due("a", &object, date)), vec![(1, Kind::Current)]);
    }

    #[test]
    fn lone_delete_markers_are_removed() {
        let rules = parse(
            "<Rule><ID>r</ID><Filter><ObjectSizeGreaterThan>5</ObjectSizeGreaterThan></Filter>\
             <Status>Enabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>\
             </Expiration></Rule>",
        )
        .unwrap();
        let today = day(2026, 1, 1);
        let lone = [version(3, at(today, 0), true, true, 0)];
        assert_eq!(kinds(&rules.due("a", &lone, today)), vec![(3, Kind::Marker)]);
        let hiding = [version(3, at(today, 0), true, true, 0), version(2, at(today, 0), false, false, 10)];
        assert_eq!(rules.due("a", &hiding, today), vec![]);
        // Objects don't expire under it.
        let object = [version(1, at(Day(0), 0), true, false, 10)];
        assert_eq!(rules.due("a", &object, today), vec![]);
    }

    #[test]
    fn noncurrent_versions_expire_from_when_they_became_noncurrent() {
        let rules = parse(
            "<Rule><ID>r</ID><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration>\
             <NoncurrentDays>2</NoncurrentDays><NewerNoncurrentVersions>1</NewerNoncurrentVersions>\
             </NoncurrentVersionExpiration></Rule>",
        )
        .unwrap();
        let first = day(2026, 1, 1);
        // Written long ago, each replaced on the 1st, 3rd and 5th.
        let versions = [
            version(4, at(Day(first.0 + 4), 12), true, false, 1),
            version(3, at(Day(first.0 + 2), 12), false, false, 1),
            version(2, at(first, 12), false, true, 0),
            version(1, at(Day(0), 0), false, false, 1),
        ];
        // The newest noncurrent version (3) is kept regardless. 2 became
        // noncurrent at noon on the 3rd, so is due from the 6th; 1 at noon on
        // the 1st, so from the 4th.
        assert_eq!(kinds(&rules.due("a", &versions, Day(first.0 + 2))), vec![]);
        let noncurrent = |successor, newer| Kind::Noncurrent { successor, newer };
        assert_eq!(kinds(&rules.due("a", &versions, Day(first.0 + 3))), vec![(1, noncurrent(2, 3))]);
        assert_eq!(kinds(&rules.due("a", &versions, Day(first.0 + 4))), vec![(1, noncurrent(2, 3))]);
        assert_eq!(kinds(&rules.due("a", &versions, Day(first.0 + 5))).len(), 2);
        assert_eq!(
            kinds(&rules.due("a", &versions, Day(first.0 + 30))),
            vec![(2, noncurrent(3, 2)), (1, noncurrent(2, 3))]
        );
        // The current version never is.
        assert_eq!(rules.due("a", &versions[..1], Day(first.0 + 30)), vec![]);
    }

    #[test]
    fn uploads_are_aborted_after_their_days() {
        let rules = parse(
            "<Rule><ID>r</ID><Prefix>tmp/</Prefix><Status>Enabled</Status><AbortIncompleteMultipartUpload>\
             <DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>",
        )
        .unwrap();
        let first = day(2026, 1, 1);
        assert!(!rules.aborts("tmp/a", at(first, 1), Day(first.0 + 1)));
        assert!(rules.aborts("tmp/a", at(first, 1), Day(first.0 + 2)));
        assert!(!rules.aborts("a", at(first, 1), Day(first.0 + 2)));
        assert!(rules.aborts_uploads() && !rules.expires_objects());
    }
}
