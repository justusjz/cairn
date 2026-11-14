//! Policies parsed and evaluated: mostly the IAM and S3 user guides'
//! examples, and what they say each does.

use super::*;

const ACCOUNT: &str = "123456789012";
const BUCKET: &str = "examplebucket";

/// A bucket policy, as it was set: each user it names by the ID the user
/// had then, which (for these tests) is its name.
fn bucket_policy(json: &str) -> Policy {
    let policy = Policy::parse(json, Kind::Bucket(BUCKET)).unwrap_or_else(|e| panic!("{json}: {e:?}"));
    let ids = policy.users().map(|(account, name)| (user_arn(account, name), name.to_owned())).collect();
    policy.with_ids(ids)
}

fn identity_policy(json: &str) -> Policy {
    Policy::parse(json, Kind::Identity).unwrap_or_else(|e| panic!("{json}: {e:?}"))
}

fn refused(json: &str, kind: Kind) -> Invalid {
    match Policy::parse(json, kind) {
        Err(e) => e,
        Ok(_) => panic!("accepted: {json}"),
    }
}

fn user(name: &str) -> Principal<'_> {
    Principal::User { account: ACCOUNT, name, id: name }
}

fn object(key: &str) -> String {
    format!("arn:aws:s3:::{BUCKET}/{key}")
}

/// A user's context, as requests will have it.
fn context_of(name: &str) -> Context {
    let mut context = Context::default();
    context.set("aws:username", name);
    context.set("aws:principalarn", format!("arn:aws:iam::{ACCOUNT}:user/{name}"));
    context
}

/// Whether `identity` and `bucket` allow `request`.
fn allowed<'p>(identity: impl IntoIterator<Item = &'p Policy>, bucket: Option<&'p Policy>, request: &Request) -> bool {
    verdict(identity, bucket, request) == Verdict::Allow
}

fn check(policy: &Policy, principal: Principal, action: &str, resource: &str, context: &Context) -> Decision {
    policy.evaluate(&Request { principal, action, resource, context })
}

#[test]
fn a_public_read_policy_allows_anyone_to_read_objects() {
    let policy = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":"*",
            "Action":["s3:GetObject","s3:GetObjectVersion"],"Resource":["arn:aws:s3:::examplebucket/*"]}]}"#,
    );
    let none = Context::default();
    assert_eq!(check(&policy, Principal::Anonymous, "s3:GetObject", &object("a/b"), &none), Decision::Allow);
    assert_eq!(check(&policy, user("alice"), "s3:getobject", &object("a"), &none), Decision::Allow);
    assert_eq!(check(&policy, Principal::Anonymous, "s3:PutObject", &object("a"), &none), Decision::NotApplicable);
    let bucket = format!("arn:aws:s3:::{BUCKET}");
    assert_eq!(check(&policy, Principal::Anonymous, "s3:ListBucket", &bucket, &none), Decision::NotApplicable);
    assert!(policy.is_public());
    // `{"AWS": "*"}` is the same.
    let aws = bucket_policy(
        r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::examplebucket/*"}}"#,
    );
    assert_eq!(check(&aws, Principal::Anonymous, "s3:GetObject", &object("a"), &none), Decision::Allow);
}

/// Which conditions keep an Allow for everyone from being public, as Block
/// Public Access sees them (probed: plans/probes/public_policy_probe.py).
#[test]
fn public_means_what_block_public_access_says() {
    let public = |condition: &str| {
        bucket_policy(&format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
                "Resource":"arn:aws:s3:::examplebucket/*","Condition":{condition}}}]}}"#
        ))
        .is_public()
    };
    let ip = |cidrs: &str| format!(r#"{{"IpAddress":{{"aws:SourceIp":{cidrs}}}}}"#);
    for (cidrs, expected) in [
        (r#""192.0.2.1/32""#, false),
        (r#""192.0.2.1""#, false),
        (r#""0.0.0.0/0""#, true),
        (r#""0.0.0.0/1""#, true),
        (r#""10.0.0.0/7""#, true),
        (r#""10.0.0.0/8""#, false),
        (r#""10.0.0.0/16""#, false),
        (r#"["10.0.0.0/8","0.0.0.0/0"]"#, true),
        (r#""::/0""#, true),
        (r#""2001:db8::/31""#, true),
        (r#""2001:db8::/32""#, false),
        (r#""2001:db8::/48""#, false),
    ] {
        assert_eq!(public(&ip(cidrs)), expected, "{cidrs}");
    }
    assert!(public(r#"{"NotIpAddress":{"aws:SourceIp":"192.0.2.1/32"}}"#));
    assert!(public(r#"{"StringEquals":{"aws:userid":"anonymous"}}"#));
    assert!(public(r#"{"StringEquals":{"aws:userid":["AIDAEXAMPLEEXAMPLE","anonymous"]}}"#));
    assert!(!public(r#"{"StringEquals":{"aws:userid":"AIDAEXAMPLEEXAMPLE"}}"#));
    assert!(!public(r#"{"StringLike":{"aws:userid":"AROAEXAMPLEEXAMPLE:*"}}"#));
    assert!(public(r#"{"StringLike":{"aws:userid":"AROA*"}}"#));
    assert!(!public(r#"{"StringEquals":{"aws:PrincipalAccount":"123456789012"}}"#));
}

#[test]
fn a_deny_wins() {
    let identity = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
    );
    let bucket = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*",
            "Resource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"],
            "Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}"#,
    );
    let mut plain = context_of("alice");
    plain.set("aws:securetransport", "false");
    let mut tls = context_of("alice");
    tls.set("aws:securetransport", "true");
    let request = |context| Request { principal: user("alice"), action: "s3:GetObject", resource: "", context };
    let resource = object("k");
    assert!(!allowed([&identity], Some(&bucket), &Request { resource: &resource, ..request(&plain) }));
    assert!(allowed([&identity], Some(&bucket), &Request { resource: &resource, ..request(&tls) }));
    assert!(allowed([&identity], None, &Request { resource: &resource, ..request(&plain) }));
    // Nothing allows: denied.
    assert!(!allowed([], None, &Request { resource: &resource, ..request(&tls) }));
}

#[test]
fn a_bucket_policy_naming_a_user_allows_it_alone() {
    let policy = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
            "Principal":{"AWS":["arn:aws:iam::123456789012:user/carlossalazar"]},
            "Action":"s3:*","Resource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"]}]}"#,
    );
    let context = Context::default();
    let resource = object("k");
    let request = |name| Request { principal: user(name), action: "s3:PutObject", resource: &resource, context: &context };
    assert!(allowed([], Some(&policy), &request("carlossalazar")));
    assert!(!allowed([], Some(&policy), &request("CarlosSalazar")), "names are case-sensitive");
    assert!(!allowed([], Some(&policy), &request("alice")));
    let anonymous = Request { principal: Principal::Anonymous, ..request("x") };
    assert!(!allowed([], Some(&policy), &anonymous));
    assert_eq!(policy.users().collect::<Vec<_>>(), [(ACCOUNT, "carlossalazar")]);
    assert!(!policy.is_public());
}

/// An account as principal allows nothing by itself (it delegates to the
/// account's identity policies), but denies all of the account's.
#[test]
fn an_account_principal_delegates_allows_and_takes_denies() {
    let allow = bucket_policy(
        r#"{"Statement":[{"Effect":"Allow","Principal":{"AWS":"123456789012"},"Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    let deny = bucket_policy(
        r#"{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:root"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    let none = Context::default();
    assert_eq!(check(&allow, user("alice"), "s3:GetObject", &object("k"), &none), Decision::NotApplicable);
    assert_eq!(check(&deny, user("alice"), "s3:GetObject", &object("k"), &none), Decision::Deny);
    assert_eq!(check(&deny, Principal::Anonymous, "s3:GetObject", &object("k"), &none), Decision::NotApplicable);
}

/// As S3 decides it (probed): a user named in `NotPrincipal` is left out,
/// whether or not the account is named too; naming the account alone leaves
/// out none of its users.
#[test]
fn not_principal_denies_all_but_whom_it_names() {
    let deny_all_but = |principals: &str| {
        bucket_policy(&format!(
            r#"{{"Statement":[{{"Effect":"Deny","NotPrincipal":{{"AWS":{principals}}},
                "Action":"s3:DeleteObject","Resource":"arn:aws:s3:::examplebucket/*"}}]}}"#
        ))
    };
    let none = Context::default();
    let both = deny_all_but(r#"["arn:aws:iam::123456789012:user/backup","arn:aws:iam::123456789012:root"]"#);
    assert_eq!(check(&both, user("backup"), "s3:DeleteObject", &object("k"), &none), Decision::NotApplicable);
    assert_eq!(check(&both, user("alice"), "s3:DeleteObject", &object("k"), &none), Decision::Deny);
    assert_eq!(check(&both, Principal::Anonymous, "s3:DeleteObject", &object("k"), &none), Decision::Deny);
    let only_user = deny_all_but(r#""arn:aws:iam::123456789012:user/backup""#);
    assert_eq!(check(&only_user, user("backup"), "s3:DeleteObject", &object("k"), &none), Decision::NotApplicable);
    let only_account = deny_all_but(r#""123456789012""#);
    assert_eq!(check(&only_account, user("backup"), "s3:DeleteObject", &object("k"), &none), Decision::Deny);
}

#[test]
fn policy_variables_reach_each_users_own_keys() {
    let policy = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::examplebucket",
             "Condition":{"StringLike":{"s3:prefix":["","home/","home/${aws:username}/*"]}}},
            {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],
             "Resource":"arn:aws:s3:::examplebucket/home/${aws:username}/*"}]}"#,
    );
    let alice = context_of("alice");
    let bucket = format!("arn:aws:s3:::{BUCKET}");
    assert_eq!(check(&policy, user("alice"), "s3:PutObject", &object("home/alice/x"), &alice), Decision::Allow);
    assert_eq!(check(&policy, user("alice"), "s3:PutObject", &object("home/bob/x"), &alice), Decision::NotApplicable);
    let mut listing = alice.clone();
    listing.set("s3:prefix", "home/alice/photos/");
    assert_eq!(check(&policy, user("alice"), "s3:ListBucket", &bucket, &listing), Decision::Allow);
    listing.set("s3:prefix", "home/bob/");
    assert_eq!(check(&policy, user("alice"), "s3:ListBucket", &bucket, &listing), Decision::NotApplicable);
    // Without a version, variables are text.
    let old = identity_policy(
        r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::examplebucket/home/${aws:username}/*"}]}"#,
    );
    assert_eq!(check(&old, user("alice"), "s3:GetObject", &object("home/alice/x"), &alice), Decision::NotApplicable);
    assert_eq!(
        check(&old, user("alice"), "s3:GetObject", &object("home/${aws:username}/x"), &alice),
        Decision::Allow
    );
}

#[test]
fn not_action_and_not_resource() {
    let policy = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[
            {"Effect":"Allow","NotAction":"s3:DeleteBucket","Resource":"arn:aws:s3:::*"},
            {"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"]}]}"#,
    );
    let none = Context::default();
    let bucket = format!("arn:aws:s3:::{BUCKET}");
    assert_eq!(check(&policy, user("a"), "s3:GetObject", &object("k"), &none), Decision::Allow);
    assert_eq!(check(&policy, user("a"), "s3:DeleteBucket", &bucket, &none), Decision::NotApplicable);
    assert_eq!(check(&policy, user("a"), "s3:GetObject", "arn:aws:s3:::other/k", &none), Decision::Deny);
    // ListAllMyBuckets is on `*`, which `arn:aws:s3:::*` isn't.
    assert_eq!(check(&policy, user("a"), "s3:ListAllMyBuckets", "*", &none), Decision::Deny);
}

#[test]
fn identity_and_bucket_policies_say_different_things() {
    let identity = Kind::Identity;
    let bucket = Kind::Bucket(BUCKET);
    let statement = |s: &str| format!(r#"{{"Version":"2012-10-17","Statement":[{s}]}}"#);
    // A principal: only in bucket policies, where it's required.
    let with = statement(r#"{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}"#);
    let without = statement(r#"{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}"#);
    assert!(Policy::parse(&with, bucket).is_ok());
    assert!(refused(&with, identity).message.contains("principal"));
    assert!(Policy::parse(&without, identity).is_ok());
    assert_eq!(refused(&without, bucket).message, "Missing required field Principal");
    // Resources: only the bucket's own in its policy.
    for resource in ["*", "arn:aws:s3:::other/*", "arn:aws:s3:::examplebucket2/*", "arn:aws:s3:::example*"] {
        let s = statement(&format!(
            r#"{{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"{resource}"}}"#
        ));
        assert_eq!(refused(&s, bucket).message, "Policy has invalid resource", "{resource}");
        assert!(Policy::parse(&s.replace(r#""Principal":"*","#, ""), identity).is_ok(), "{resource}");
    }
    // Other services' actions: only in identity policies.
    let kms = statement(r#"{"Effect":"Allow","Action":"kms:Decrypt","Resource":"*"}"#);
    assert!(Policy::parse(&kms, identity).is_ok());
    // An Id: only in bucket policies.
    let id = r#"{"Id":"x","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#;
    assert!(Policy::parse(id, bucket).is_ok());
    assert!(Policy::parse(&id.replace(r#""Principal":"*","#, ""), identity).is_err());
}


/// What PutBucketPolicy refused, and with which message, when probed
/// (`plans/probes/policy-aws*.jsonl`).
#[test]
fn refuses_what_s3_refuses() {
    let bucket = Kind::Bucket(BUCKET);
    let demo = r#"{"AWS":"arn:aws:iam::123456789012:user/demo"}"#;
    // A statement with these fields (`null`: without it), and the defaults
    // for the others.
    let statement = |fields: &str| {
        let mut all = vec![
            ("Effect".to_owned(), r#""Allow""#.to_owned()),
            ("Principal".to_owned(), demo.to_owned()),
            ("Action".to_owned(), r#""s3:GetObject""#.to_owned()),
            ("Resource".to_owned(), r#""arn:aws:s3:::examplebucket/*""#.to_owned()),
        ];
        let given: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&format!("{{{fields}}}")).unwrap();
        for (name, value) in given {
            match value {
                serde_json::Value::Null => all.retain(|(n, _)| *n != name),
                value => match all.iter_mut().find(|(n, _)| *n == name) {
                    Some(field) => field.1 = value.to_string(),
                    None => all.push((name, value.to_string())),
                },
            }
        }
        let fields: Vec<String> = all.iter().map(|(n, v)| format!("\"{n}\":{v}")).collect();
        format!(r#"{{"Version":"2012-10-17","Statement":[{{{}}}]}}"#, fields.join(","))
    };
    let condition = |c: &str| statement(&format!(r#""Condition":{c}"#));
    let cases = [
        ("not json".to_owned(), "Policies must be valid JSON and the first byte must be '{'"),
        ("[]".to_owned(), "Policies must be valid JSON and the first byte must be '{'"),
        ("{}".to_owned(), "Missing required field Statement"),
        (r#"{"Version":"2012-10-17"}"#.to_owned(), "Missing required field Statement"),
        (r#"{"Version":"2012-10-17","Statement":[]}"#.to_owned(), "Could not parse the policy: Statement is empty!"),
        (statement("").replace("2012-10-17", "2010-01-01"), "The policy must contain a valid version string"),
        (statement("").replacen('{', r#"{"Extra":"x","#, 1), "Unknown field Extra"),
        (statement("").replacen('{', r#"{"Version":"2012-10-17","#, 1), "Statement/policy already has instance of Version"),
        (
            statement("").replacen(r#""Effect":"Allow""#, r#""Effect":"Allow","Effect":"Deny""#, 1),
            "Statement/policy already has instance of Effect",
        ),
        (statement(r#""Effect":null,"effect":"Allow""#), "Unknown field effect"),
        (statement(r#""Extra":"x""#), "Unknown field Extra"),
        (statement(r#""Sid":5"#), "Invalid policy syntax."),
        (statement(r#""Effect":null"#), "Missing required field Effect"),
        (statement(r#""Principal":null"#), "Missing required field Principal"),
        (statement(r#""Principal":"alice""#), "Invalid policy syntax."),
        (statement(r#""Principal":{"AWS":"arn:aws:iam::123456789012:user/*"}"#), "Invalid principal in policy"),
        (statement(r#""Principal":{"AWS":"1234"}"#), "Invalid principal in policy"),
        (statement(r#""Principal":{"CanonicalUser":"abc"}"#), "Invalid principal in policy"),
        (statement(r#""Principal":{"Group":"x"}"#), "Invalid policy syntax."),
        (statement(r#""Principal":{"aws":"arn:aws:iam::123456789012:user/demo"}"#), "Invalid policy syntax."),
        (statement(r#""Principal":{"AWS":[]}"#), "Missing required field Principal cannot be empty!"),
        (statement(&format!(r#""NotPrincipal":{demo}"#)), "Statement/policy already has instance of Principal"),
        (statement(&format!(r#""Principal":null,"NotPrincipal":{demo}"#)), "Allow with NotPrincipal is not allowed."),
        (statement(r#""Action":null"#), "Missing required field Action"),
        (statement(r#""Action":"GetObject""#), "Policy has invalid action"),
        (statement(r#""Action":"s3:Frobnicate""#), "Policy has invalid action"),
        (statement(r#""Action":"s3:Frob*""#), "Policy has invalid action"),
        (statement(r#""Action":"kms:Decrypt""#), "Policy has invalid action"),
        (statement(r#""NotAction":"s3:PutObject""#), "Statement/policy already has instance of Action"),
        (statement(r#""Action":[]"#), "Missing required field Action cannot be empty!"),
        (statement(r#""Resource":null"#), "Statement is missing required element"),
        (statement(r#""Resource":"*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"arn:aws:s3:::some-other-bucket-x1/*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"arn:aws:s3:::examplebucket*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"arn:aws:s3:::example*/*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"arn:aws:s3:::*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"arn:aws:s3:eu-north-1::examplebucket/*""#), "Policy has invalid resource"),
        (statement(r#""Resource":"examplebucket/*""#), "Policy has invalid resource"),
        (statement(r#""Resource":[]"#), "Action does not apply to any resource(s) in statement"),
        (statement(r#""Resource":"arn:aws:s3:::examplebucket""#), "Action does not apply to any resource(s) in statement"),
        (statement(r#""Action":"s3:ListBucket""#), "Action does not apply to any resource(s) in statement"),
        (statement(r#""Action":["s3:GetObject","s3:ListBucket"]"#), "Action does not apply to any resource(s) in statement"),
        (
            statement(r#""Action":"s3:ListAllMyBuckets","Resource":"arn:aws:s3:::examplebucket""#),
            "Policy has invalid action",
        ),
        (statement(r#""Action":"s3:CreateBucket","Resource":"arn:aws:s3:::examplebucket""#), "Policy has invalid action"),
        (condition(r#"{"StringEquals":{"s3:frobnicate":"x"}}"#), "Policy has an invalid condition key"),
        (condition(r#"{"StringEquals":{"kms:ViaService":"x"}}"#), "Policy has an invalid condition key"),
        (condition(r#"{"StringEquals":{"frob:x":"x"}}"#), "Policy has an invalid condition key"),
        (condition(r#"{"StringEquals":{"frobnicate":"x"}}"#), "Policy has an invalid condition key"),
        (
            condition(r#"{"StringEquals":{"s3:prefix":"x"}}"#),
            "Conditions do not apply to combination of actions and resources in statement",
        ),
        (
            condition(r#"{"Null":{"s3:versionid":"true"}}"#),
            "Conditions do not apply to combination of actions and resources in statement",
        ),
        (
            statement(r#""Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"],"Condition":{"StringEquals":{"s3:prefix":"x"}}"#),
            "Conditions do not apply to combination of actions and resources in statement",
        ),
        (
            statement(r#""Action":"s3:Get*","Condition":{"StringEquals":{"s3:prefix":"x"}}"#),
            "Conditions do not apply to combination of actions and resources in statement",
        ),
        (
            statement(r#""Action":"s3:PutObject","Condition":{"StringEquals":{"s3:ExistingObjectTag/a":"x"}}"#),
            "Conditions do not apply to combination of actions and resources in statement",
        ),
        (condition(r#"{"StringEqualz":{"aws:Referer":"x"}}"#), "Invalid Condition type : StringEqualz"),
        (condition(r#"{"stringequals":{"aws:Referer":"x"}}"#), "Invalid Condition type : stringequals"),
        (condition(r#"{"NullIfExists":{"aws:Referer":"true"}}"#), "Invalid Condition type : NullIfExists"),
        (condition(r#"{"ForSomeValues:StringEquals":{"aws:Referer":"x"}}"#), "Invalid condition prefix: ForSomeValues"),
        (condition(r#"{"IpAddress":{"aws:SourceIp":"1.2.3.4/40"}}"#), "Invalid IP address in Conditions"),
        (condition(r#"{"Null":{"aws:SourceIp":"false"}}"#), "Invalid IP address in Conditions"),
        (condition(r#"{"StringEquals":{"aws:Referer":{"a":"b"}}}"#), "Invalid policy syntax."),
    ];
    for (json, wanted) in cases {
        let invalid = refused(&json, bucket);
        assert_eq!((invalid.code, invalid.message.as_str()), ("MalformedPolicy", wanted), "{json}");
    }
    // The size limit is the normalized policy's: whitespace doesn't count.
    let many = |n: usize| {
        let statements: Vec<String> = (0..n)
            .map(|i| {
                format!(
                    r#"{{"Sid":"s{i}","Effect":"Allow","Principal":{demo},"Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}}"#
                )
            })
            .collect();
        format!(r#"{{"Version":"2012-10-17","Statement":[{}]}}"#, statements.join(","))
    };
    assert_eq!(
        refused(&many(200), bucket).message,
        "Normalized policy document exceeds the maximum allowed size of 20480 bytes"
    );
    bucket_policy(&format!("{}{}", statement(""), " ".repeat(21 << 10)));
    // What Cairn can't decide yet is refused as not implemented, not ignored;
    // but only once S3 would take the policy.
    let tags = condition(r#"{"StringEquals":{"s3:ExistingObjectTag/team":"x"}}"#);
    assert_eq!(refused(&tags, bucket).code, "NotImplemented");
    let both = condition(r#"{"StringEquals":{"s3:ExistingObjectTag/team":"x","s3:prefix":"x"}}"#);
    assert_eq!(refused(&both, bucket).code, "MalformedPolicy");
    // Statement IDs must be unique in identity policies (IAM's rule).
    let twice = r#"{"Statement":[{"Sid":"a","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
                                 {"Sid":"a","Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    assert!(refused(twice, Kind::Identity).message.contains("unique"));
}

/// What PutBucketPolicy took when probed, and how GetBucketPolicy gave it
/// back.
#[test]
fn accepts_and_normalizes_as_s3_does() {
    let reads_back = |json: &str, wanted: &str| {
        assert_eq!(bucket_policy(json).normalized(), wanted, "{json}");
    };
    let demo = "arn:aws:iam::123456789012:user/demo";
    reads_back(
        &format!(
            r#"{{"Statement":{{"Sid":"x","Effect":"allow","Principal":{{"AWS":"{demo}"}},"Action":["s3:getobject"],
                "Resource":"arn:aws:s3:::examplebucket/*","Condition":{{"NumericLessThan":{{"s3:signatureAge":600000}},
                "Bool":{{"aws:SecureTransport":true}}}}}}}}"#
        ),
        &format!(
            r#"{{"Version":"2008-10-17","Statement":[{{"Sid":"x","Effect":"Allow","Principal":{{"AWS":"{demo}"}},"Action":"s3:getobject","Resource":"arn:aws:s3:::examplebucket/*","Condition":{{"Bool":{{"aws:SecureTransport":"true"}},"NumericLessThan":{{"s3:signatureAge":"600000"}}}}}}]}}"#
        ),
    );
    reads_back(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"123456789012"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    reads_back(
        &format!(
            "{{\n  \"Version\": \"2012-10-17\",\n  \"Statement\": [ {{ \"Effect\": \"Deny\", \"Principal\": {{\"AWS\": [\"{demo}\"]}},\n    \"Action\": [\"s3:GetObject\"], \"Resource\": [\"arn:aws:s3:::examplebucket/*\"] }} ]\n}}"
        ),
        &format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{demo}"}},"Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}}]}}"#
        ),
    );
    for json in [
        // The same Sid twice, a Sid with spaces, an empty one.
        r#"{"Statement":[{"Sid":"a","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"},
            {"Sid":"a","Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::examplebucket/*"},
            {"Sid":"Allow get requests.","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"},
            {"Sid":"","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
        // Wildcards in actions, which some of their actions fit.
        r#"{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/alice","123456789012"]},
            "Action":["s3:Get*","s3:List*"],"Resource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"]}]}"#,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:Get*","Resource":"arn:aws:s3:::examplebucket"}]}"#,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:List*","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
        r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
        // `?` and variables in keys.
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
            "Resource":["arn:aws:s3:::examplebucket/a/?","arn:aws:s3:::examplebucket/home/${aws:username}/*"]}]}"#,
        // `s3:prefix` with every action that takes it, or `s3:*`, or NotAction.
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::examplebucket",
            "Condition":{"StringEquals":{"S3:Prefix":"x"}}}]}"#,
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::examplebucket/*",
            "Condition":{"StringEquals":{"s3:prefix":"x"}}}]}"#,
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","NotAction":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*",
            "Condition":{"StringEquals":{"s3:prefix":"x"}}}]}"#,
        // Unknown `aws:` keys, any values, no values, no conditions at all.
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*",
            "Condition":{"StringEquals":{"aws:frobnicate":"x","AWS:REFERER":[]},"NumericLessThan":{"s3:signatureAge":"ten"},
            "Bool":{"aws:SecureTransport":"yes"},"IpAddress":{"aws:Referer":"1.2.3.4"},"StringLike":{}}}]}"#,
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*","Condition":{}}]}"#,
        // Keys of features Cairn doesn't have are always missing.
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::examplebucket/*",
            "Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-1a2b3c4d"}}}]}"#,
        // Services, which never call Cairn; NotPrincipal with Deny.
        r#"{"Statement":[{"Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":"s3:PutObject",
            "Resource":"arn:aws:s3:::examplebucket/logs/*"},
            {"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::123456789012:user/demo"},"Action":"s3:GetObject",
            "Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
        // An Id.
        r#"{"Id":"my-policy","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    ] {
        bucket_policy(json);
    }
    // Identity policies may name what isn't S3's.
    identity_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*",
            "Condition":{"StringEquals":{"kms:ViaService":"s3.eu-north-1.amazonaws.com"}}}]}"#,
    );
}

/// A lowercase Effect is the Effect (probed).
#[test]
fn a_lowercase_deny_denies() {
    let policy = bucket_policy(
        r#"{"Statement":[{"Effect":"deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    assert_eq!(check(&policy, user("a"), "s3:GetObject", &object("k"), &Context::default()), Decision::Deny);
}

/// Keys from AWS services Cairn isn't don't hold: the conditions over them
/// decide as a request without them would.
#[test]
fn absent_keys_are_missing() {
    let policy = bucket_policy(
        r#"{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::examplebucket/*",
            "Condition":{"StringNotEquals":{"aws:SourceVpce":"vpce-1a2b3c4d"}}}]}"#,
    );
    assert_eq!(check(&policy, user("a"), "s3:GetObject", &object("k"), &Context::default()), Decision::Deny);
}

/// A user a bucket policy names is the one that had the name when it was
/// set: not one made with the name since (S3 keeps the user's unique ID).
/// One that's gone is shown by its ID.
#[test]
fn names_users_as_they_were() {
    let json = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["arn:aws:iam::{ACCOUNT}:user/bob","arn:aws:iam::{ACCOUNT}:user/carol"]}},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*","Condition":{{"StringEquals":{{"aws:PrincipalArn":"arn:aws:iam::{ACCOUNT}:user/bob"}}}}}}]}}"#
    );
    let policy = Policy::parse(&json, Kind::Bucket(BUCKET)).unwrap();
    let bob = user_arn(ACCOUNT, "bob");
    let policy = policy.with_ids([(bob.clone(), "id-1".to_owned())].into());
    let mut context = context_of("bob");
    context.set("aws:PrincipalArn", &bob);
    let resource = object("k");
    let request = |id| Request {
        principal: Principal::User { account: ACCOUNT, name: "bob", id },
        action: "s3:GetObject",
        resource: &resource,
        context: &context,
    };
    assert_eq!(policy.evaluate(&request("id-1")), Decision::Allow);
    assert_eq!(policy.evaluate(&request("id-2")), Decision::NotApplicable);
    // Carol wasn't there when it was set: it names no one (its condition
    // holding, as the context is bob's).
    let carol = Request { principal: Principal::User { account: ACCOUNT, name: "carol", id: "carol" }, ..request("id-1") };
    assert_eq!(policy.evaluate(&carol), Decision::NotApplicable);

    // Shown with bob's ID once bob is gone; the condition's ARN is a value,
    // which stays.
    assert_eq!(policy.shown(Kind::Bucket(BUCKET), &HashMap::new()), policy.normalized());
    let shown = policy.shown(Kind::Bucket(BUCKET), &[(bob.clone(), "id-1".to_owned())].into());
    assert_eq!(shown, policy.normalized().replacen(&format!("\"{bob}\""), "\"id-1\"", 1));
    assert!(shown.contains(&format!("\"aws:PrincipalArn\":\"{bob}\"")), "{shown}");
}

#[test]
fn an_action_sees_only_the_s3_keys_it_takes() {
    // As probed: a request may carry `?prefix=`, `?max-keys=` or `x-amz-acl`
    // whatever it does, but S3 has those keys only for the actions that
    // take them, so conditions on them hold for those alone.
    let policy = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/bob"},
            "Action":"s3:*","Resource":["arn:aws:s3:::examplebucket","arn:aws:s3:::examplebucket/*"],
            "Condition":{"StringLike":{"s3:prefix":"bob/*"}}}]}"#,
    );
    let mut request = context_of("bob");
    request.set("s3:prefix", "bob/x");
    request.set("s3:max-keys", "5000");
    request.set("s3:x-amz-acl", "private");
    request.set("s3:authType", "REST-HEADER");
    let bucket = format!("arn:aws:s3:::{BUCKET}");
    let decide = |action, resource: &str| check(&policy, user("bob"), action, resource, &request.clone().for_action(action));
    assert_eq!(decide("s3:ListBucket", &bucket), Decision::Allow);
    for action in ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] {
        assert_eq!(decide(action, &object("secret")), Decision::NotApplicable, "{action}");
    }
    let kept = |action| request.clone().for_action(action);
    let listing = kept("s3:ListBucket");
    assert!(listing.get("s3:prefix").is_some() && listing.get("s3:max-keys").is_some());
    assert!(listing.get("s3:x-amz-acl").is_none());
    let put = kept("s3:PutObject");
    assert!(put.get("s3:prefix").is_none() && put.get("s3:max-keys").is_none());
    assert_eq!(put.get("s3:x-amz-acl"), Some(&["private".to_owned()][..]));
    // Global keys, and the `s3:` ones every action takes, stay.
    assert!(put.get("aws:username").is_some() && put.get("s3:authtype").is_some());
    // An action that isn't S3's takes no `s3:` key.
    assert!(kept("iam:GetUser").get("s3:authType").is_none());
}

/// A permissions boundary caps what identity policies allow, as AWS's does
/// (probed: see `plans/boundaries.md`): a Deny in it denies; a bucket policy
/// that names the user, or everyone, allows within the account beyond it,
/// but one that names the account delegates to the identity policies,
/// which it caps; across accounts, both sides must allow, the boundary too.
#[test]
fn a_boundary_caps_identity_policies() {
    let s3_all = identity_policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#);
    let list_only = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}"#,
    );
    let deny_secret = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},
            {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/secret/*"}]}"#,
    );
    let context = context_of("alice");
    let resource = object("k");
    let secret = object("secret/k");
    let request = |resource: &'static str| Request { principal: user("alice"), action: "s3:GetObject", resource, context: &context };
    let get = Request { resource: &resource, ..request("") };
    let get_secret = Request { resource: &secret, ..request("") };
    let decide = |boundary: Option<&Policy>, bucket: Option<&Policy>, request: &Request, cross: bool| {
        verdict_across([&s3_all], Caps { boundary, session: None }, bucket, request, cross)
    };
    assert_eq!(decide(None, None, &get, false), Verdict::Allow);
    assert_eq!(decide(Some(&list_only), None, &get, false), Verdict::OutsideBoundary);
    assert_eq!(decide(Some(&deny_secret), None, &get, false), Verdict::Allow);
    assert_eq!(decide(Some(&deny_secret), None, &get_secret, false), Verdict::BoundaryDeny);
    // Neither allows: it's the boundary that doesn't (probed).
    assert_eq!(verdict_across([], Caps { boundary: Some(&list_only), session: None }, None, &get, false), Verdict::OutsideBoundary);
    // A boundary alone allows nothing.
    assert_eq!(verdict_across([], Caps { boundary: Some(&s3_all), session: None }, None, &get, false), Verdict::ImplicitDeny);

    let by_user = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/alice"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    let by_everyone = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*",
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    let by_account = bucket_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"123456789012"},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::examplebucket/*"}]}"#,
    );
    assert_eq!(decide(Some(&list_only), Some(&by_user), &get, false), Verdict::Allow);
    assert_eq!(verdict_across([], Caps { boundary: Some(&list_only), session: None }, Some(&by_user), &get, false), Verdict::Allow);
    assert_eq!(decide(Some(&list_only), Some(&by_everyone), &get, false), Verdict::Allow);
    assert_eq!(decide(Some(&list_only), Some(&by_account), &get, false), Verdict::OutsideBoundary);
    assert_eq!(decide(Some(&deny_secret), Some(&by_user), &get_secret, false), Verdict::BoundaryDeny);
    // Across accounts: the boundary caps the identity side, which must
    // allow too.
    assert_eq!(decide(Some(&list_only), Some(&by_user), &get, true), Verdict::OutsideBoundary);
    assert_eq!(decide(Some(&s3_all), Some(&by_user), &get, true), Verdict::Allow);

    assert_eq!(
        Verdict::OutsideBoundary.why("s3:GetObject", Some("arn:aws:iam::123456789012:policy/b")),
        "because no permissions boundary allows the s3:GetObject action"
    );
    assert_eq!(
        Verdict::BoundaryDeny.why("s3:GetObject", Some("arn:aws:iam::123456789012:policy/b")),
        "with an explicit deny in a permissions boundary: arn:aws:iam::123456789012:policy/b"
    );
}

/// A bucket policy names a user by its ARN, path and all, and decides by
/// the user's ID: the one it named, renamed or moved since (probed).
#[test]
fn names_users_by_their_ids_whatever_their_arns() {
    let json = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:user/team/bob"}},
            "Action":"s3:GetObject","Resource":"arn:aws:s3:::{BUCKET}/*"}}]}}"#
    );
    let policy = Policy::parse(&json, Kind::Bucket(BUCKET)).unwrap();
    assert_eq!(policy.users().collect::<Vec<_>>(), [(ACCOUNT, "team/bob")]);
    let arn = user_arn(ACCOUNT, "team/bob");
    let policy = policy.with_ids([(arn.clone(), "id-1".to_owned())].into());
    let context = Context::default();
    let resource = object("k");
    let request = |name, id| Request {
        principal: Principal::User { account: ACCOUNT, name, id },
        action: "s3:GetObject",
        resource: &resource,
        context: &context,
    };
    assert_eq!(policy.evaluate(&request("bob", "id-1")), Decision::Allow);
    assert_eq!(policy.evaluate(&request("robert", "id-1")), Decision::Allow, "renamed");
    assert_eq!(policy.evaluate(&request("bob", "id-2")), Decision::NotApplicable);
    // Shown by its ARN now.
    let renamed = format!("arn:aws:iam::{ACCOUNT}:user/other/robert");
    let shown = policy.shown(Kind::Bucket(BUCKET), &[(arn.clone(), renamed.clone())].into());
    assert!(shown.contains(&renamed) && !shown.contains(&arn), "{shown}");
}

/// Tags are condition keys whose tag keys are any case (probed).
#[test]
fn tag_keys_are_any_case() {
    let policy = identity_policy(
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetUser","Resource":"*",
            "Condition":{"StringEquals":{"aws:ResourceTag/Team":"a","aws:PrincipalTag/dept":"x"}}}]}"#,
    );
    let mut context = Context::default();
    context.set("aws:ResourceTag/team", "a");
    context.set("aws:PrincipalTag/Dept", "x");
    let arn = user_arn(ACCOUNT, "bob");
    assert_eq!(check(&policy, user("alice"), "iam:GetUser", &arn, &context), Decision::Allow);
    context.set("aws:ResourceTag/team", "A");
    assert_eq!(check(&policy, user("alice"), "iam:GetUser", &arn, &context), Decision::NotApplicable, "values aren't");
}

/// A trust policy (`Principal`) of the probed shapes, refused or taken as
/// IAM takes it, with IAM's messages (probed: `plans/roles.md`).
#[test]
fn trust_policies_are_checked_as_iam_checks_them() {
    let demo = format!("arn:aws:iam::{ACCOUNT}:user/demo");
    let statement = |rest: &str| format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow",{rest}}}]}}"#);
    let refusals = [
        (statement(r#""Action":"sts:AssumeRole""#), "Missing required field Principal"),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole","Resource":"*""#)), "Has prohibited field Resource"),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"s3:GetObject""#)), "AssumeRole policy may only specify STS AssumeRole actions."),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:GetSessionToken""#)), "AssumeRole policy may only specify STS AssumeRole actions."),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:*""#)), "AssumeRole policy may only specify STS AssumeRole actions."),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"*""#)), "AssumeRole policy may only specify STS AssumeRole actions."),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"NotAction":"s3:*""#)), "AssumeRole policy may only specify STS AssumeRole actions."),
        (
            statement(&format!(r#""Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:user/*"}},"Action":"sts:AssumeRole""#)),
            r#"Invalid principal in policy: "AWS":"arn:aws:iam::123456789012:user/*""#,
        ),
        (
            statement(&format!(r#""Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:role/probe-*"}},"Action":"sts:AssumeRole""#)),
            r#"Invalid principal in policy: "AWS":"arn:aws:iam::123456789012:role/probe-*""#,
        ),
        (
            format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","NotPrincipal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole"}}]}}"#),
            "Allow with NotPrincipal is not allowed.",
        ),
        (r#"{"Version":"2012-10-17","Statement":[]}"#.to_owned(), "Could not parse the policy: Statement is empty!"),
        ("{".to_owned(), "This policy contains invalid Json"),
    ];
    for (json, message) in refusals {
        let e = refused(&json, Kind::Trust);
        assert_eq!((e.code, e.message.as_str()), ("MalformedPolicy", message), "{json}");
    }
    // Taken, and kept as IAM shows them: an account as its root, one
    // value as itself, principals sorted, no Version as 2008-10-17.
    let taken = [
        (statement(r#""Principal":{"AWS":"*"},"Action":"sts:AssumeRole""#), None),
        (
            statement(&format!(r#""Principal":{{"AWS":"{ACCOUNT}"}},"Action":["sts:AssumeRole"]"#)),
            Some(format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:root"}},"Action":"sts:AssumeRole"}}]}}"#)),
        ),
        (
            statement(&format!(r#""Principal":{{"AWS":["{demo}","arn:aws:iam::{ACCOUNT}:root"]}},"Action":"sts:AssumeRole""#)),
            Some(format!(
                r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":["arn:aws:iam::{ACCOUNT}:root","{demo}"]}},"Action":"sts:AssumeRole"}}]}}"#
            )),
        ),
        (
            statement(&format!(r#""Principal":{{"Federated":"arn:aws:iam::{ACCOUNT}:oidc-provider/example.com"}},"Action":"sts:AssumeRoleWithWebIdentity""#)),
            None,
        ),
        (statement(r#""Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole""#), None),
        (statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:TagSession""#)), None),
        (
            statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole","Condition":{{"StringEquals":{{"aws:Frobnicate":"x"}}}}"#)),
            None,
        ),
        (
            statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole","Condition":{{"StringLike":{{"sts:RoleSessionName":"x*"}}}}"#)),
            None,
        ),
        (
            format!(r#"{{"Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole"}}]}}"#),
            Some(format!(r#"{{"Version":"2008-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole"}}]}}"#)),
        ),
    ];
    for (json, normalized) in taken {
        let policy = Policy::parse(&json, Kind::Trust).unwrap_or_else(|e| panic!("{json}: {e:?}"));
        if let Some(normalized) = normalized {
            assert_eq!(policy.normalized(), normalized);
        }
    }
    // What it names, for IAM to check that they exist.
    let policy = Policy::parse(
        &statement(&format!(
            r#""Principal":{{"AWS":["{demo}","arn:aws:iam::{ACCOUNT}:role/team/r","arn:aws:sts::{ACCOUNT}:assumed-role/r/s"]}},"Action":"sts:AssumeRole""#
        )),
        Kind::Trust,
    )
    .unwrap();
    assert_eq!(policy.users().collect::<Vec<_>>(), [(ACCOUNT, "demo")]);
    assert_eq!(policy.roles().collect::<Vec<_>>(), [(ACCOUNT, "team/r")]);
    assert_eq!(policy.sessions().collect::<Vec<_>>(), [(ACCOUNT, "r", "s")]);
    // STS's keys that Cairn doesn't decide are refused, as other
    // undecidable keys are.
    let e = refused(
        &statement(&format!(r#""Principal":{{"AWS":"{demo}"}},"Action":"sts:AssumeRole","Condition":{{"StringEquals":{{"sts:Frobnicate":"x"}}}}"#)),
        Kind::Trust,
    );
    assert_eq!(e.code, "NotImplemented");
    // Roles and sessions are bucket policies' principals too; wildcards
    // aren't.
    let principal = |who: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{who}"}},"Action":"s3:GetObject","Resource":"{}"}}]}}"#,
            object("*")
        )
    };
    let policy = Policy::parse(&principal(&format!("arn:aws:iam::{ACCOUNT}:role/team/r")), Kind::Bucket(BUCKET)).unwrap();
    assert_eq!(policy.roles().collect::<Vec<_>>(), [(ACCOUNT, "team/r")]);
    let policy = Policy::parse(&principal(&format!("arn:aws:sts::{ACCOUNT}:assumed-role/r/s")), Kind::Bucket(BUCKET)).unwrap();
    assert_eq!(policy.sessions().collect::<Vec<_>>(), [(ACCOUNT, "r", "s")]);
    let e = refused(&principal(&format!("arn:aws:iam::{ACCOUNT}:role/*")), Kind::Bucket(BUCKET));
    assert_eq!(e.message, "Invalid principal in policy");
}

/// A role's session, as policies see it: its role `r` (ID `rid`).
fn session(name: &str) -> Principal<'_> {
    Principal::Session { account: ACCOUNT, role: "r", id: "rid", session: name }
}

/// Bucket policies naming a session allow past its caps; naming its role,
/// within them; the reasons denied ones give (probed: `plans/roles.md`).
#[test]
fn sessions_are_capped_by_their_role_and_session_policies() {
    let bucket = Policy::parse(
        &format!(
            r#"{{"Version":"2012-10-17","Statement":[
                {{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:role/team/r"}},"Action":"s3:GetObject","Resource":"{}"}},
                {{"Effect":"Allow","Principal":{{"AWS":"arn:aws:sts::{ACCOUNT}:assumed-role/r/named"}},"Action":"s3:GetObject","Resource":"{}"}}]}}"#,
            object("role/*"),
            object("session/*")
        ),
        Kind::Bucket(BUCKET),
    )
    .unwrap()
    .with_ids([(format!("arn:aws:iam::{ACCOUNT}:role/team/r"), "rid".to_owned())].into());
    let list_only = identity_policy(&format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::{BUCKET}"}}]}}"#
    ));
    let read_all = identity_policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#);
    let context = Context::default();
    let decide = |who: Principal, key: &str, identity: &[&Policy], caps: Caps| {
        let resource = object(key);
        let request = Request { principal: who, action: "s3:GetObject", resource: &resource, context: &context };
        verdict_across(identity.iter().copied(), caps, Some(&bucket), &request, false)
    };
    let none = Caps::default();
    let session_list: [&Policy; 1] = [&list_only];
    let capped_by_session = Caps { boundary: None, session: Some(&session_list) };
    let bounded = Caps { boundary: Some(&list_only), session: None };
    let no_session_policies: [&Policy; 0] = [];
    let restricted = Caps { boundary: None, session: Some(&no_session_policies) };

    // Naming the role: any of its sessions, within their caps.
    assert_eq!(decide(session("any"), "role/k", &[], none), Verdict::Allow);
    assert_eq!(decide(session("any"), "role/k", &[], capped_by_session), Verdict::OutsideSession);
    assert_eq!(decide(session("any"), "role/k", &[], bounded), Verdict::OutsideBoundary);
    // Naming the session: it alone, past its caps.
    assert_eq!(decide(session("named"), "session/k", &[], capped_by_session), Verdict::Allow);
    assert_eq!(decide(session("named"), "session/k", &[], bounded), Verdict::Allow);
    assert_eq!(decide(session("other"), "session/k", &[], none), Verdict::ImplicitDeny);
    // The role's own policies, within the caps; the reasons in order.
    assert_eq!(decide(session("any"), "elsewhere", &[&read_all], none), Verdict::Allow);
    assert_eq!(decide(session("any"), "elsewhere", &[&read_all], capped_by_session), Verdict::OutsideSession);
    assert_eq!(decide(session("any"), "elsewhere", &[], capped_by_session), Verdict::ImplicitDeny);
    assert_eq!(decide(session("any"), "elsewhere", &[&read_all], restricted), Verdict::OutsideSession);
    assert_eq!(
        decide(session("any"), "elsewhere", &[&read_all], Caps { boundary: Some(&list_only), session: Some(&session_list) }),
        Verdict::OutsideBoundary
    );
    // A user is never the role's session.
    assert_eq!(decide(user("r"), "role/k", &[], none), Verdict::ImplicitDeny);
}

/// A trust policy allows by naming the principal itself, or its account
/// (with the principal's identity policies), never by identity policies
/// alone (probed).
#[test]
fn trust_policies_decide_who_assumes_a_role() {
    let trusting = |who: &str| {
        Policy::parse(
            &format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{who}"}},"Action":"sts:AssumeRole"}}]}}"#),
            Kind::Trust,
        )
        .unwrap()
        .with_ids([(format!("arn:aws:iam::{ACCOUNT}:user/alice"), "alice".to_owned())].into())
    };
    let may_assume = identity_policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}"#);
    let s3_only = identity_policy(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#);
    let context = Context::default();
    let role = format!("arn:aws:iam::{ACCOUNT}:role/r");
    let request = Request { principal: user("alice"), action: "sts:AssumeRole", resource: &role, context: &context };
    let decide = |trust: &Policy, identity: &[&Policy], caps: Caps| trust_allows(identity.iter().copied(), caps, trust, &request);
    let alice = trusting(&format!("arn:aws:iam::{ACCOUNT}:user/alice"));
    let account = trusting(&format!("arn:aws:iam::{ACCOUNT}:root"));
    let other = trusting(&format!("arn:aws:iam::{ACCOUNT}:user/bob"));
    assert!(decide(&alice, &[], Caps::default()));
    // Past a boundary that doesn't allow it.
    assert!(decide(&alice, &[], Caps { boundary: Some(&s3_only), session: None }));
    assert!(!decide(&account, &[], Caps::default()));
    assert!(decide(&account, &[&may_assume], Caps::default()));
    assert!(!decide(&account, &[&may_assume], Caps { boundary: Some(&s3_only), session: None }));
    assert!(!decide(&other, &[&may_assume], Caps::default()));
}
