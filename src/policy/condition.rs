//! A statement's `Condition`: operators, and how each compares the request's
//! values of a key with the policy's (see the IAM user guide's "condition
//! operators" and "multivalued keys").
//!
//! - Several operators, or keys under one, must all hold; several values of
//!   one key, any one of them (a negated operator: none of them).
//! - A key the request doesn't have makes a positive operator false and a
//!   negated one true, but `...IfExists` makes any operator true, and `Null`
//!   is about exactly that.
//! - `ForAllValues:` holds if every one of the request's values (none too)
//!   does; `ForAnyValue:` if any one does (so not if there's none).

use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::STANDARD};

use super::{
    Context, Invalid,
    pattern::{Pattern, Syntax, arn_matches},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    StringEquals,
    StringEqualsIgnoreCase,
    StringLike,
    NumericEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    DateEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
    Bool,
    BinaryEquals,
    IpAddress,
    ArnLike,
    Null,
}

/// The operators, by name: each is its positive form, negated or not.
const OPERATORS: &[(&str, Op, bool)] = &[
    ("StringEquals", Op::StringEquals, false),
    ("StringNotEquals", Op::StringEquals, true),
    ("StringEqualsIgnoreCase", Op::StringEqualsIgnoreCase, false),
    ("StringNotEqualsIgnoreCase", Op::StringEqualsIgnoreCase, true),
    ("StringLike", Op::StringLike, false),
    ("StringNotLike", Op::StringLike, true),
    ("NumericEquals", Op::NumericEquals, false),
    ("NumericNotEquals", Op::NumericEquals, true),
    ("NumericLessThan", Op::NumericLessThan, false),
    ("NumericLessThanEquals", Op::NumericLessThanEquals, false),
    ("NumericGreaterThan", Op::NumericGreaterThan, false),
    ("NumericGreaterThanEquals", Op::NumericGreaterThanEquals, false),
    ("DateEquals", Op::DateEquals, false),
    ("DateNotEquals", Op::DateEquals, true),
    ("DateLessThan", Op::DateLessThan, false),
    ("DateLessThanEquals", Op::DateLessThanEquals, false),
    ("DateGreaterThan", Op::DateGreaterThan, false),
    ("DateGreaterThanEquals", Op::DateGreaterThanEquals, false),
    ("Bool", Op::Bool, false),
    ("BinaryEquals", Op::BinaryEquals, false),
    ("IpAddress", Op::IpAddress, false),
    ("NotIpAddress", Op::IpAddress, true),
    // ArnEquals and ArnLike behave the same, as AWS says.
    ("ArnEquals", Op::ArnLike, false),
    ("ArnLike", Op::ArnLike, false),
    ("ArnNotEquals", Op::ArnLike, true),
    ("ArnNotLike", Op::ArnLike, true),
    ("Null", Op::Null, false),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Set {
    ForAllValues,
    ForAnyValue,
}

/// One key's test under one operator.
#[derive(Clone, Debug, PartialEq)]
pub struct Condition {
    op: Op,
    negated: bool,
    set: Option<Set>,
    if_exists: bool,
    /// As written; looked up regardless of case.
    key: String,
    values: Vec<String>,
}

/// An operator's name: `[ForAllValues:|ForAnyValue:]Name[IfExists]`, or
/// S3's error for it (probed).
fn operator(name: &str) -> Result<(Op, bool, Option<Set>, bool), Invalid> {
    let (set, rest) = match name.split_once(':') {
        Some(("ForAllValues", rest)) => (Some(Set::ForAllValues), rest),
        Some(("ForAnyValue", rest)) => (Some(Set::ForAnyValue), rest),
        Some((prefix, _)) => return Err(Invalid::malformed(format!("Invalid condition prefix: {prefix}"))),
        None => (None, name),
    };
    let unknown = || Invalid::malformed(format!("Invalid Condition type : {name}"));
    let (rest, if_exists) = match rest.strip_suffix("IfExists") {
        Some(rest) => (rest, true),
        None => (rest, false),
    };
    let &(_, op, negated) = OPERATORS.iter().find(|(n, _, _)| *n == rest).ok_or_else(unknown)?;
    if op == Op::Null && if_exists {
        return Err(unknown());
    }
    Ok((op, negated, set, if_exists))
}

/// Checks an operator's name (see `operator`).
pub fn check_operator(name: &str) -> Result<(), Invalid> {
    operator(name).map(|_| ())
}

impl Condition {
    /// A condition as a policy writes it: `operator` (its name), with `key`'s
    /// values. S3 takes any values (probed): one that isn't what the
    /// operator compares (a number, a date, ...) matches nothing, and no
    /// values at all match nothing either.
    pub fn new(operator_name: &str, key: &str, values: Vec<String>) -> Result<Condition, Invalid> {
        let (op, negated, set, if_exists) = operator(operator_name)?;
        Ok(Condition { op, negated, set, if_exists, key: key.to_owned(), values })
    }

    /// Whether the condition holds for a request with `context`; policy
    /// variables in values only with `variables`.
    pub fn holds(&self, context: &Context, variables: bool) -> bool {
        let given = context.get(&self.key).filter(|values| !values.is_empty());
        if self.op == Op::Null {
            // `true`: the key is missing; `false`: it's there.
            return self.values.iter().any(|v| boolean(v) == Some(given.is_none()));
        }
        let Some(given) = given else {
            return self.if_exists
                || match self.set {
                    Some(Set::ForAllValues) => true,
                    Some(Set::ForAnyValue) => false,
                    None => self.negated,
                };
        };
        let variables = variables.then_some(context);
        let one = |value: &str| self.values.iter().any(|v| self.compare(value, v, variables)) != self.negated;
        match self.set {
            Some(Set::ForAllValues) => given.iter().all(|v| one(v)),
            Some(Set::ForAnyValue) => given.iter().any(|v| one(v)),
            // A single-valued key; a multivalued one without a set operator
            // is taken as any of its values.
            None if self.negated => given.iter().all(|v| one(v)),
            None => given.iter().any(|v| one(v)),
        }
    }

    /// Whether the request's `value` matches the policy's `wanted`, by the
    /// operator's positive form.
    fn compare(&self, value: &str, wanted: &str, variables: Option<&Context>) -> bool {
        let pattern = |wildcards| Pattern::new(wanted, Syntax { wildcards, variables });
        let numbers = || number(value).zip(number(wanted));
        let dates = || date(value).zip(date(wanted));
        match self.op {
            Op::StringEquals => pattern(false).is_some_and(|p| p.matches(value, false)),
            Op::StringEqualsIgnoreCase => pattern(false).is_some_and(|p| p.matches(value, true)),
            Op::StringLike => pattern(true).is_some_and(|p| p.matches(value, false)),
            Op::NumericEquals => numbers().is_some_and(|(a, b)| a == b),
            Op::NumericLessThan => numbers().is_some_and(|(a, b)| a < b),
            Op::NumericLessThanEquals => numbers().is_some_and(|(a, b)| a <= b),
            Op::NumericGreaterThan => numbers().is_some_and(|(a, b)| a > b),
            Op::NumericGreaterThanEquals => numbers().is_some_and(|(a, b)| a >= b),
            Op::DateEquals => dates().is_some_and(|(a, b)| a == b),
            Op::DateLessThan => dates().is_some_and(|(a, b)| a < b),
            Op::DateLessThanEquals => dates().is_some_and(|(a, b)| a <= b),
            Op::DateGreaterThan => dates().is_some_and(|(a, b)| a > b),
            Op::DateGreaterThanEquals => dates().is_some_and(|(a, b)| a >= b),
            Op::Bool => boolean(value).is_some() && boolean(value) == boolean(wanted),
            Op::BinaryEquals => match (STANDARD.decode(value), STANDARD.decode(wanted)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            },
            Op::IpAddress => match (value.parse::<IpAddr>(), cidr(wanted)) {
                (Ok(ip), Some((network, bits))) => in_network(ip.to_canonical(), network, bits),
                _ => false,
            },
            Op::ArnLike => arn_matches(wanted, value, variables),
            Op::Null => unreachable!("Null is about the key, not its values"),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Whether the condition limits a statement to fixed values of `key`:
    /// a positive operator (not over a set), values without wildcards. As
    /// Block Public Access takes them (probed): an `aws:SourceIp` block
    /// must be no wider than a /8 (IPv4) or a /32 (IPv6); an `aws:userid`
    /// not anonymous requests' (`anonymous`), but a role's sessions'
    /// (`StringLike` `<role ID>:*`) are fixed.
    pub fn fixes(&self, key: &str) -> bool {
        let fixed = |v: &str| !v.contains(['*', '?']);
        self.key.eq_ignore_ascii_case(key)
            && !self.negated
            && !self.if_exists
            && self.set.is_none()
            && self.op != Op::Null
            && !self.values.is_empty()
            && self.values.iter().all(|v| match key.to_ascii_lowercase().as_str() {
                "aws:sourceip" => cidr(v).is_some_and(|(address, bits)| bits >= if address.is_ipv4() { 8 } else { 32 }),
                "aws:userid" => {
                    let sessions = v.strip_suffix(":*").filter(|_| self.op == Op::StringLike);
                    !v.eq_ignore_ascii_case("anonymous") && fixed(sessions.unwrap_or(v))
                }
                _ => fixed(v),
            })
    }
}

fn number(text: &str) -> Option<f64> {
    text.trim().parse::<f64>().ok().filter(|n| n.is_finite())
}

fn boolean(text: &str) -> Option<bool> {
    match text {
        t if t.eq_ignore_ascii_case("true") => Some(true),
        t if t.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// A block of addresses: an address and the bits of it that count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    bits: u8,
}

impl Network {
    /// A CIDR block, or one address (all of its bits).
    pub fn parse(text: &str) -> Option<Network> {
        cidr(text).map(|(address, bits)| Network { address, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        in_network(ip.to_canonical(), self.address, self.bits)
    }
}

/// Whether `text` is an address, or a CIDR block.
pub fn is_cidr(text: &str) -> bool {
    cidr(text).is_some()
}

/// A CIDR block, or one address (all of its bits).
fn cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (address, bits) = match text.split_once('/') {
        Some((address, bits)) => (address, Some(bits.parse::<u8>().ok()?)),
        None => (text, None),
    };
    let address = address.parse::<IpAddr>().ok()?.to_canonical();
    let max = if address.is_ipv4() { 32 } else { 128 };
    let bits = bits.unwrap_or(max);
    (bits <= max).then_some((address, bits))
}

fn in_network(ip: IpAddr, network: IpAddr, bits: u8) -> bool {
    let mask = |bits: u8, width: u32| if bits == 0 { 0 } else { u128::MAX << (width - bits as u32) };
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = mask(bits, 32) as u32;
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = mask(bits, 128);
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    }
}

/// A time, in seconds since the Unix epoch: ISO 8601 (`2026-11-11`,
/// `2026-11-11T12:00:00Z`, with fractions or an offset), or epoch seconds.
pub fn date(text: &str) -> Option<f64> {
    let text = text.trim();
    if let Ok(epoch) = text.parse::<f64>() {
        return epoch.is_finite().then_some(epoch);
    }
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit()).then(|| s.parse::<i64>().ok()).flatten();
    let (day, time) = match text.split_once(['T', 't']) {
        Some((day, time)) => (day, Some(time)),
        None => (text, None),
    };
    let mut parts = day.split('-');
    let (year, month, mday) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || year.len() != 4 || month.len() != 2 || mday.len() != 2 {
        return None;
    }
    let (year, month, mday) = (digits(year)?, digits(month)?, digits(mday)?);
    if !(1..=12).contains(&month) || !(1..=days_in_month(year, month)).contains(&mday) {
        return None;
    }
    let mut seconds = (days_from_civil(year, month, mday) * 86400) as f64;
    if let Some(time) = time {
        let (clock, offset) = match time.find(['Z', 'z', '+', '-']) {
            Some(i) => (&time[..i], &time[i..]),
            None => (time, ""),
        };
        let (hms, fraction) = match clock.split_once('.') {
            Some((hms, fraction)) if !fraction.is_empty() && fraction.bytes().all(|b| b.is_ascii_digit()) => {
                (hms, format!("0.{fraction}").parse::<f64>().ok()?)
            }
            Some(_) => return None,
            None => (clock, 0.0),
        };
        let fields: Vec<&str> = hms.split(':').collect();
        if !(2..=3).contains(&fields.len()) || fields.iter().any(|f| f.len() != 2) {
            return None;
        }
        let (hour, minute) = (digits(fields[0])?, digits(fields[1])?);
        let second = fields.get(2).map_or(Some(0), |s| digits(s))?;
        if hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        seconds += (hour * 3600 + minute * 60 + second) as f64 + fraction;
        seconds -= match offset {
            "" | "Z" | "z" => 0.0,
            offset => {
                let sign = if offset.starts_with('-') { -1.0 } else { 1.0 };
                let (hours, minutes) = offset[1..].split_once(':')?;
                if hours.len() != 2 || minutes.len() != 2 {
                    return None;
                }
                sign * (digits(hours)? * 3600 + digits(minutes)? * 60) as f64
            }
        };
    }
    Some(seconds)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a date of the proleptic Gregorian calendar
/// (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// How Cairn treats a condition key a policy names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Support {
    /// Requests carry it, when S3's would.
    Evaluated,
    /// No request to Cairn ever has it (as no request to S3 from outside AWS
    /// through a VPC endpoint, say), so it's always missing, rightly.
    Absent,
    /// S3's requests would have it, and Cairn's don't yet: a policy that
    /// names it would be decided wrongly, so it's refused (501).
    Unsupported,
}

/// The global keys (`aws:`), lowercase; a trailing `/` takes any suffix.
const GLOBAL_KEYS: &[(&str, Support)] = &[
    ("aws:currenttime", Support::Evaluated),
    ("aws:epochtime", Support::Evaluated),
    ("aws:principalaccount", Support::Evaluated),
    ("aws:principalarn", Support::Evaluated),
    // The signing user's tags.
    ("aws:principaltag/", Support::Evaluated),
    ("aws:principalisawsservice", Support::Evaluated),
    ("aws:principaltype", Support::Evaluated),
    ("aws:referer", Support::Evaluated),
    ("aws:requestedregion", Support::Evaluated),
    ("aws:resourceaccount", Support::Evaluated),
    ("aws:securetransport", Support::Evaluated),
    ("aws:sourceip", Support::Evaluated),
    ("aws:useragent", Support::Evaluated),
    ("aws:userid", Support::Evaluated),
    ("aws:username", Support::Evaluated),
    ("aws:viaawsservice", Support::Evaluated),
    ("aws:calledvia", Support::Absent),
    ("aws:calledviafirst", Support::Absent),
    ("aws:calledvialast", Support::Absent),
    ("aws:ec2instancesourceprivateipv4", Support::Absent),
    ("aws:ec2instancesourcevpc", Support::Absent),
    ("aws:federatedprovider", Support::Absent),
    ("aws:multifactorauthage", Support::Absent),
    ("aws:multifactorauthpresent", Support::Absent),
    ("aws:principalorgid", Support::Absent),
    ("aws:principalorgpaths", Support::Absent),
    ("aws:principalservicename", Support::Absent),
    ("aws:principalservicenameslist", Support::Absent),

    ("aws:resourceorgid", Support::Absent),
    ("aws:resourceorgpaths", Support::Absent),
    ("aws:sourceaccount", Support::Absent),
    ("aws:sourcearn", Support::Absent),
    ("aws:sourceidentity", Support::Absent),
    ("aws:sourceorgid", Support::Absent),
    ("aws:sourceorgpaths", Support::Absent),
    ("aws:sourcevpc", Support::Absent),
    ("aws:sourcevpcarn", Support::Absent),
    ("aws:sourcevpce", Support::Absent),
    ("aws:tokenissuetime", Support::Absent),
    ("aws:vpcsourceip", Support::Absent),
    // A user's tags, and those IAM's requests set (see `iam`). Never on
    // S3's: a bucket's tags are its `aws:ResourceTag`s only with its ABAC
    // enabled, which it's not by default (probed), and Cairn has no
    // PutBucketAbac; nor does Cairn's CreateBucket take tags.
    ("aws:requesttag/", Support::Evaluated),
    ("aws:resourcetag/", Support::Evaluated),
    ("aws:tagkeys", Support::Evaluated),
];

/// The `s3:` keys Cairn's requests carry, lowercase; a trailing `/` takes
/// any suffix (a tag key).
const S3_EVALUATED: &[&str] = &[
    "s3:authtype",
    "s3:delimiter",
    "s3:if-match",
    "s3:if-none-match",
    "s3:max-keys",
    "s3:object-lock-legal-hold",
    "s3:object-lock-mode",
    "s3:object-lock-remaining-retention-days",
    "s3:object-lock-retain-until-date",
    "s3:prefix",
    "s3:resourceaccount",
    "s3:signatureage",
    "s3:signatureversion",
    "s3:versionid",
    "s3:x-amz-acl",
    "s3:x-amz-content-sha256",
    "s3:x-amz-copy-source",
    "s3:x-amz-grant-full-control",
    "s3:x-amz-grant-read",
    "s3:x-amz-grant-read-acp",
    "s3:x-amz-grant-write",
    "s3:x-amz-grant-write-acp",
    "s3:x-amz-metadata-directive",
    "s3:x-amz-server-side-encryption",
    "s3:x-amz-server-side-encryption-aws-kms-key-id",
    "s3:x-amz-server-side-encryption-customer-algorithm",
    "s3:x-amz-storage-class",
    "s3:x-amz-website-redirect-location",
];

/// The `s3:` keys of what Cairn doesn't have: access points, access grants,
/// batch jobs, replication, inventory, log delivery, annotations.
const S3_ABSENT: &[&str] = &[
    "s3:accessgrantscope",
    "s3:accessgrantsinstancearn",
    "s3:accessgrantslocationscope",
    "s3:accesspointnetworkorigin",
    "s3:accesspointtag/",
    "s3:annotation-prefix",
    "s3:dataaccesspointaccount",
    "s3:dataaccesspointarn",
    "s3:deliverysourcearn",
    "s3:destinationregion",
    "s3:existingjoboperation",
    "s3:existingjobpriority",
    "s3:inventoryaccessibleoptionalfields",
    "s3:isreplicationpauserequest",
    "s3:jobsuspendedcause",
    "s3:logtype",
    "s3:max-annotation-results",
    "s3:requestjoboperation",
    "s3:requestjobpriority",
    "s3:x-amz-object-annotation-directive",
];

/// How Cairn treats `key`, or `None` if it's not a key of S3's (or a global
/// one). Regardless of case.
pub fn support(key: &str) -> Option<Support> {
    let key = key.to_ascii_lowercase();
    let named = |entry: &str| match entry.strip_suffix('/') {
        Some(prefix) => key.strip_prefix(prefix).and_then(|rest| rest.strip_prefix('/')).is_some_and(|tag| !tag.is_empty()),
        None => key == entry,
    };
    if let Some(&(_, support)) = GLOBAL_KEYS.iter().find(|(entry, _)| named(entry)) {
        return Some(support);
    }
    if !key.starts_with("s3:") {
        return None;
    }
    if S3_EVALUATED.iter().any(|entry| named(entry)) {
        return Some(Support::Evaluated);
    }
    if S3_ABSENT.iter().any(|entry| named(entry)) {
        return Some(Support::Absent);
    }
    // The rest of S3's keys (existing object and bucket tags, event holds,
    // TLS versions, the tags a request sets: PutObjectTagging's are in its
    // body, which is read after it's authorized, ...) aren't evaluated yet.
    let known = super::s3_actions::CONDITION_KEYS.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        let entry = entry.split_once('/').map_or(entry.clone(), |(prefix, _)| format!("{prefix}/"));
        named(&entry)
    });
    known.then_some(Support::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn condition(op: &str, key: &str, values: &[&str]) -> Condition {
        Condition::new(op, key, values.iter().map(|v| v.to_string()).collect()).unwrap()
    }

    fn context(pairs: &[(&str, &[&str])]) -> Context {
        let mut context = Context::default();
        for (key, values) in pairs {
            context.set_all(key, values.iter().map(|v| v.to_string()).collect());
        }
        context
    }

    #[test]
    fn strings() {
        let c = context(&[("s3:prefix", &["home/alice/"]), ("aws:username", &["alice"])]);
        assert!(condition("StringEquals", "s3:prefix", &["x", "home/alice/"]).holds(&c, true));
        assert!(!condition("StringEquals", "S3:Prefix", &["HOME/alice/"]).holds(&c, true));
        assert!(condition("StringEqualsIgnoreCase", "s3:prefix", &["HOME/alice/"]).holds(&c, true));
        assert!(condition("StringLike", "s3:prefix", &["home/*"]).holds(&c, true));
        assert!(!condition("StringEquals", "s3:prefix", &["home/*"]).holds(&c, true));
        assert!(condition("StringLike", "s3:prefix", &["home/${aws:username}/*"]).holds(&c, true));
        // Variables only in policies of 2012-10-17.
        assert!(!condition("StringLike", "s3:prefix", &["home/${aws:username}/*"]).holds(&c, false));
        // Negated: none of the values.
        assert!(!condition("StringNotEquals", "s3:prefix", &["x", "home/alice/"]).holds(&c, true));
        assert!(condition("StringNotLike", "s3:prefix", &["public/*", "tmp/*"]).holds(&c, true));
        // An unresolved variable matches nothing; so its negation holds.
        assert!(!condition("StringEquals", "s3:prefix", &["${aws:userid}"]).holds(&c, true));
        assert!(condition("StringNotEquals", "s3:prefix", &["${aws:userid}"]).holds(&c, true));
    }

    #[test]
    fn missing_keys() {
        let empty = Context::default();
        assert!(!condition("StringEquals", "aws:referer", &["x"]).holds(&empty, true));
        assert!(condition("StringNotEquals", "aws:referer", &["x"]).holds(&empty, true));
        assert!(condition("NumericNotEquals", "s3:max-keys", &["1"]).holds(&empty, true));
        assert!(!condition("NumericLessThan", "s3:max-keys", &["1"]).holds(&empty, true));
        assert!(condition("StringEqualsIfExists", "aws:referer", &["x"]).holds(&empty, true));
        assert!(condition("NotIpAddress", "aws:sourceip", &["10.0.0.0/8"]).holds(&empty, true));
        assert!(condition("Null", "aws:referer", &["true"]).holds(&empty, true));
        assert!(!condition("Null", "aws:referer", &["false"]).holds(&empty, true));
        let c = context(&[("aws:referer", &["x"])]);
        assert!(condition("Null", "aws:referer", &["false"]).holds(&c, true));
        assert!(!condition("StringEqualsIfExists", "aws:referer", &["y"]).holds(&c, true));
    }

    #[test]
    fn sets() {
        let tags = context(&[("s3:requestobjecttagkeys", &["project", "owner"])]);
        let none = Context::default();
        let all = condition("ForAllValues:StringEquals", "s3:RequestObjectTagKeys", &["project", "owner", "x"]);
        assert!(all.holds(&tags, true));
        assert!(all.holds(&none, true), "no values: all of them do");
        let all_one = condition("ForAllValues:StringEquals", "s3:RequestObjectTagKeys", &["project"]);
        assert!(!all_one.holds(&tags, true));
        let any = condition("ForAnyValue:StringEquals", "s3:RequestObjectTagKeys", &["owner"]);
        assert!(any.holds(&tags, true));
        assert!(!any.holds(&none, true), "no values: none of them does");
        let none_secret = condition("ForAllValues:StringNotEquals", "s3:RequestObjectTagKeys", &["secret"]);
        assert!(none_secret.holds(&tags, true));
        assert!(none_secret.holds(&none, true));
        let any_not = condition("ForAnyValue:StringNotEquals", "s3:RequestObjectTagKeys", &["project"]);
        assert!(any_not.holds(&tags, true));
    }

    #[test]
    fn numbers_dates_booleans_and_binary() {
        let c = context(&[
            ("s3:max-keys", &["10"]),
            ("aws:currenttime", &["2026-11-11T12:00:00Z"]),
            ("aws:securetransport", &["false"]),
            ("x:binary", &["aGVsbG8="]),
        ]);
        assert!(condition("NumericLessThanEquals", "s3:max-keys", &["10"]).holds(&c, true));
        assert!(condition("NumericEquals", "s3:max-keys", &["10.0"]).holds(&c, true));
        assert!(!condition("NumericGreaterThan", "s3:max-keys", &["10"]).holds(&c, true));
        assert!(condition("DateLessThan", "aws:CurrentTime", &["2026-11-12"]).holds(&c, true));
        assert!(condition("DateGreaterThan", "aws:CurrentTime", &["2026-11-11T12:59:59+01:00"]).holds(&c, true));
        assert!(condition("DateEquals", "aws:CurrentTime", &["1794398400"]).holds(&c, true));
        assert!(condition("Bool", "aws:SecureTransport", &["false"]).holds(&c, true));
        assert!(!condition("Bool", "aws:SecureTransport", &["true"]).holds(&c, true));
        assert!(condition("BinaryEquals", "x:binary", &["aGVsbG8="]).holds(&c, true));
    }

    #[test]
    fn addresses() {
        let v4 = context(&[("aws:sourceip", &["203.0.113.7"])]);
        let v6 = context(&[("aws:sourceip", &["2001:db8::1"])]);
        let mapped = context(&[("aws:sourceip", &["::ffff:203.0.113.7"])]);
        let net = condition("IpAddress", "aws:SourceIp", &["203.0.113.0/24", "2001:db8::/32"]);
        assert!(net.holds(&v4, true));
        assert!(net.holds(&v6, true));
        assert!(net.holds(&mapped, true));
        assert!(condition("IpAddress", "aws:SourceIp", &["203.0.113.7"]).holds(&v4, true));
        assert!(!condition("IpAddress", "aws:SourceIp", &["203.0.113.8"]).holds(&v4, true));
        assert!(condition("IpAddress", "aws:SourceIp", &["0.0.0.0/0"]).holds(&v4, true));
        assert!(condition("NotIpAddress", "aws:SourceIp", &["10.0.0.0/8"]).holds(&v4, true));
    }

    #[test]
    fn arns() {
        let c = context(&[("aws:principalarn", &["arn:aws:iam::123456789012:user/alice"])]);
        assert!(condition("ArnLike", "aws:PrincipalArn", &["arn:aws:iam::123456789012:user/*"]).holds(&c, true));
        assert!(condition("ArnEquals", "aws:PrincipalArn", &["arn:aws:iam::*:user/alice"]).holds(&c, true));
        assert!(condition("ArnNotLike", "aws:PrincipalArn", &["arn:aws:iam::123456789012:user/bob"]).holds(&c, true));
    }

    #[test]
    fn refuses_bad_operators() {
        let message = |op: &str| check_operator(op).err().map(|e| e.message);
        assert_eq!(message("StringEqualz").as_deref(), Some("Invalid Condition type : StringEqualz"));
        assert_eq!(message("stringequals").as_deref(), Some("Invalid Condition type : stringequals"));
        assert_eq!(message("NullIfExists").as_deref(), Some("Invalid Condition type : NullIfExists"));
        assert_eq!(message("ForSomeValues:StringEquals").as_deref(), Some("Invalid condition prefix: ForSomeValues"));
        assert_eq!(message("StringEqualsIfExists"), None);
        assert_eq!(message("ForAnyValue:StringLikeIfExists"), None);
    }

    /// As S3 decides them (probed): values that aren't what the operator
    /// compares match nothing; `True` is `true`.
    #[test]
    fn odd_values_match_nothing() {
        let c = context(&[("aws:securetransport", &["true"]), ("s3:signatureage", &["100"]), ("aws:referer", &["x"])]);
        assert!(!condition("Bool", "aws:SecureTransport", &["yes"]).holds(&c, true));
        assert!(condition("Bool", "aws:SecureTransport", &["True"]).holds(&c, true));
        assert!(!condition("NumericLessThan", "s3:signatureAge", &["ten"]).holds(&c, true));
        assert!(!condition("DateLessThan", "aws:CurrentTime", &["2026-13-01"]).holds(&c, true));
        assert!(!condition("StringEquals", "aws:Referer", &[]).holds(&c, true));
        assert!(condition("StringNotEquals", "aws:Referer", &[]).holds(&c, true));
    }

    #[test]
    fn parses_dates() {
        assert_eq!(date("1970-01-01"), Some(0.0));
        assert_eq!(date("1970-01-02T00:00:01Z"), Some(86401.0));
        assert_eq!(date("2000-03-01T00:00:00Z"), Some(951868800.0));
        assert_eq!(date("1970-01-01T01:00:00+01:00"), Some(0.0));
        assert_eq!(date("1970-01-01T00:00:00.5Z"), Some(0.5));
        assert_eq!(date("1970-01-01T00:00Z"), Some(0.0));
        assert_eq!(date("1700000000"), Some(1700000000.0));
        assert_eq!(date("2026-11-11T25:00:00Z"), None);
        assert_eq!(date("11/11/2026"), None);
    }

    #[test]
    fn knows_the_keys() {
        assert_eq!(support("aws:SourceIp"), Some(Support::Evaluated));
        assert_eq!(support("AWS:SOURCEVPCE"), Some(Support::Absent));
        assert_eq!(support("s3:prefix"), Some(Support::Evaluated));
        assert_eq!(support("s3:RequestObjectTag/Project"), Some(Support::Unsupported));
        assert_eq!(support("s3:RequestObjectTag/"), None);
        assert_eq!(support("s3:ExistingObjectTag/Project"), Some(Support::Unsupported));
        assert_eq!(support("s3:object-lock-mode"), Some(Support::Evaluated));
        assert_eq!(support("s3:object-lock-event-hold"), Some(Support::Unsupported));
        assert_eq!(support("s3:DataAccessPointArn"), Some(Support::Absent));
        assert_eq!(support("aws:PrincipalTag/team"), Some(Support::Evaluated));
        assert_eq!(support("aws:ResourceTag/team"), Some(Support::Evaluated));
        assert_eq!(support("s3:frobnicate"), None);
        assert_eq!(support("aws:frobnicate"), None);
        assert_eq!(support("kms:ViaService"), None);
    }
}
