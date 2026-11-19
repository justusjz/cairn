//! S3 Tables' names and ARNs: table buckets', namespaces' and tables', as
//! AWS's rules have them (the user guide's naming rules, and botocore's
//! model for the ARNs' shapes).

use crate::s3::buckets::head::REGION;

/// Prefixes and suffixes no table bucket's name may have.
const RESERVED_PREFIXES: [&str; 4] = ["xn--", "sthree-", "amzn-s3-demo-", "aws"];
const RESERVED_SUFFIXES: [&str; 4] = ["-s3alias", "--ol-s3", "--x-s3", "--table-s3"];

/// The suffix of every table's storage bucket's name, and only theirs (no
/// S3 bucket may have it: see `s3::buckets::create`).
pub const STORAGE_SUFFIX: &str = "--table-s3";

/// Why a name isn't one, as the error's message says it.
pub type Invalid = String;

/// Whether `name` is a table bucket's: 3 to 63 lowercase letters, digits
/// and hyphens, a letter or digit at both ends, without a reserved prefix
/// or suffix.
pub fn bucket_name(name: &str) -> Result<(), Invalid> {
    let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let valid = (3..=63).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && edge(name.chars().next())
        && edge(name.chars().last())
        && !RESERVED_PREFIXES.iter().any(|p| name.starts_with(p))
        && !RESERVED_SUFFIXES.iter().any(|s| name.ends_with(s));
    match valid {
        true => Ok(()),
        false => Err(format!(
            "The specified bucket name is not valid: {name}. Table bucket names must be 3 to 63 \
             lowercase letters, numbers and hyphens, begin and end with a letter or number, and \
             not begin or end with a reserved prefix or suffix."
        )),
    }
}

/// Whether `name` is a namespace's (`what`: "namespace") or a table's
/// ("table"): 1 to 255 lowercase letters, digits and underscores, starting
/// with a letter or digit; a namespace's not with `aws`.
pub fn name(what: &str, name: &str) -> Result<(), Invalid> {
    let valid = (1..=255).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !(what == "namespace" && name.starts_with("aws"));
    match valid {
        true => Ok(()),
        false => Err(format!(
            "The specified {what} name is not valid: {name}. It must be 1 to 255 lowercase \
             letters, numbers and underscores, and begin with a letter or number{}.",
            if what == "namespace" {
                ", and not with aws"
            } else {
                ""
            }
        )),
    }
}

/// Table bucket `name`'s ARN, of `account`.
pub fn bucket_arn(account: &str, name: &str) -> String {
    format!("arn:aws:s3tables:{REGION}:{account}:bucket/{name}")
}

/// A table's ARN: its bucket's, and its ID (which a rename keeps).
pub fn table_arn(bucket_arn: &str, id: &str) -> String {
    format!("{bucket_arn}/table/{id}")
}

/// What an ARN of S3 Tables' names.
#[derive(Debug, PartialEq, Eq)]
pub enum Arn {
    /// A table bucket: its account and name.
    Bucket { account: String, name: String },
    /// A table: its bucket's account and name, and its ID.
    Table {
        account: String,
        bucket: String,
        id: String,
    },
}

/// What `arn` names, if it's an ARN of S3 Tables' shape (botocore's
/// patterns); `Ok(None)` if it is, but of another region or service, which
/// has nothing in Cairn.
pub fn parse_arn(arn: &str) -> Result<Option<Arn>, Invalid> {
    let invalid = || format!("The specified ARN is not valid: {arn}");
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    let [prefix, partition, service, region, account, path] = parts[..] else {
        return Err(invalid());
    };
    let partition_ok = partition.strip_prefix("aws").is_some_and(|rest| {
        rest.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if prefix != "arn"
        || !partition_ok
        || service.is_empty()
        || !service
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || account.len() != 12
        || !account.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let Some(rest) = path.strip_prefix("bucket/") else {
        return Err(invalid());
    };
    let (bucket, table) = match rest.split_once('/') {
        Some((bucket, rest)) => match rest.strip_prefix("table/") {
            Some(id) => (bucket, Some(id)),
            None => return Err(invalid()),
        },
        None => (rest, None),
    };
    let bucket_ok = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    let table_ok = table.is_none_or(|id| {
        (1..=255).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    });
    if !bucket_ok || !table_ok {
        return Err(invalid());
    }
    if partition != "aws" || service != "s3tables" || region != REGION {
        return Ok(None);
    }
    Ok(Some(match table {
        None => Arn::Bucket {
            account: account.to_owned(),
            name: bucket.to_owned(),
        },
        Some(id) => Arn::Table {
            account: account.to_owned(),
            bucket: bucket.to_owned(),
            id: id.to_owned(),
        },
    }))
}

/// A new table's storage bucket's name, from its ID, in the shape of AWS's
/// warehouse locations: the ID's first 18 characters, a hyphen, 34 random
/// lowercase letters and digits, and the suffix (63 characters in all).
pub fn storage_name(id: &uuid::Uuid) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut random = [0u8; 34];
    getrandom::fill(&mut random).expect("the system's random source");
    let random: String = random
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!("{}-{random}{STORAGE_SUFFIX}", &id.to_string()[..18])
}

/// Whether `bucket` is a table's storage.
pub fn is_storage(bucket: &str) -> bool {
    bucket.ends_with(STORAGE_SUFFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_names() {
        assert!(bucket_name("analytics").is_ok());
        assert!(bucket_name("a-1").is_ok());
        for bad in [
            "ab",
            "Analytics",
            "a_b",
            "a.b",
            "-ab",
            "ab-",
            "aws-data",
            "xn--ab",
            "data--x-s3",
            "data--table-s3",
            &"a".repeat(64),
        ] {
            assert!(bucket_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn namespace_and_table_names() {
        assert!(name("namespace", "sales_2026").is_ok());
        assert!(name("table", "aws_data").is_ok());
        assert!(name("namespace", "aws_data").is_err());
        for bad in ["", "_a", "a-b", "A", "a.b", &"a".repeat(256)] {
            assert!(name("table", bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn arns() {
        let bucket = bucket_arn("111122223333", "data");
        assert_eq!(
            bucket,
            "arn:aws:s3tables:us-east-1:111122223333:bucket/data"
        );
        assert_eq!(
            parse_arn(&bucket).unwrap(),
            Some(Arn::Bucket {
                account: "111122223333".into(),
                name: "data".into()
            })
        );
        assert_eq!(
            parse_arn(&table_arn(&bucket, "0b9a")).unwrap(),
            Some(Arn::Table {
                account: "111122223333".into(),
                bucket: "data".into(),
                id: "0b9a".into()
            })
        );
        assert_eq!(
            parse_arn("arn:aws:s3tables:eu-west-1:111122223333:bucket/data").unwrap(),
            None
        );
        for bad in [
            "data",
            "arn:aws:s3tables:us-east-1:1111:bucket/data",
            "arn:aws:s3tables:us-east-1:111122223333:table/data",
            "arn:aws:s3tables:us-east-1:111122223333:bucket/data/view/x",
        ] {
            assert!(parse_arn(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn storage_names() {
        let id = uuid::Uuid::new_v4();
        let name = storage_name(&id);
        assert_eq!(name.len(), 63);
        assert!(is_storage(&name));
        assert!(name.starts_with(&id.to_string()[..18]));
    }
}
