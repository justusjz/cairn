use super::*;
use crate::policy::{Kind, Policy};

const ACCOUNT: &str = "123456789012";

fn team(list_all_buckets: bool, list_policies: bool) -> Use {
    Use::Team {
        team: "oneai".into(),
        bucket_prefix: Some("oneai-dev-".into()),
        list_all_buckets,
        list_policies,
    }
}

/// Every template's policies are valid identity policies, within IAM's
/// size for a managed policy, and tagged with their template.
#[test]
fn makes_valid_policies() {
    let uses = [
        team(false, false),
        team(true, true),
        Use::BucketAccess {
            buckets: "logs-*".into(),
            levels: vec![
                Level::Read,
                Level::Write,
                Level::DeleteVersion,
                Level::Manage,
            ],
            name: None,
            path: None,
        },
        Use::MfaGuard {
            name: None,
            path: None,
        },
    ];
    for using in uses {
        for made in using.make(ACCOUNT).unwrap() {
            Policy::parse(&made.document, Kind::Identity)
                .unwrap_or_else(|e| panic!("{}: {e:?}", made.name));
            let size = made.document.chars().filter(|c| !c.is_whitespace()).count();
            assert!(
                size <= crate::managed::MAX_DOCUMENT,
                "{}: {size}",
                made.name
            );
            assert!(
                made.tags
                    .contains(&(TEMPLATE_TAG.to_owned(), using.template().id.to_owned()))
            );
            crate::managed::check_tags(&made.tags).unwrap();
        }
    }
}

/// A team's policies are at Cairn's path, not the team's own, and name the
/// boundary by its ARN there; the opt-ins are in only when asked for.
#[test]
fn teams_policies_are_out_of_their_reach() {
    let made = team(false, false).make(ACCOUNT).unwrap();
    assert!(made.iter().all(|m| m.path == "/cairn/teams/oneai/"));
    let boundary = format!("arn:aws:iam::{ACCOUNT}:policy/cairn/teams/oneai/oneai-team");
    assert_eq!(
        made.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        ["oneai-team", "oneai-member"]
    );
    assert!(made[0].document.contains(&boundary));
    assert!(
        made.iter().all(|m| !m.document.contains("ListAllMyBuckets")
            && !m.document.contains("iam:ListPolicies"))
    );
    let made = team(true, true).make(ACCOUNT).unwrap();
    assert!(
        made[0].document.contains("s3:ListAllMyBuckets")
            && made[0].document.contains("iam:ListPolicies")
    );
    // Members see all buckets' names if the team does; they don't list
    // policies.
    assert!(
        made[1].document.contains("s3:ListAllMyBuckets")
            && !made[1].document.contains("iam:ListPolicies")
    );
    // No cluster, and nothing at another path.
    assert!(made.iter().all(|m| !m.document.contains("cairn:")));
}

#[test]
fn refuses_what_would_reach_too_far() {
    let team = |name: &str, prefix: Option<&str>| Use::Team {
        team: name.into(),
        bucket_prefix: prefix.map(str::to_owned),
        list_all_buckets: false,
        list_policies: false,
    };
    assert!(team("", None).make(ACCOUNT).is_err());
    assert!(team("a/b", None).make(ACCOUNT).is_err());
    assert!(team("cairn", None).make(ACCOUNT).is_err());
    // A prefix that's too short, or a pattern, would take others' buckets.
    assert!(team("x", None).make(ACCOUNT).is_err());
    assert!(team("x", Some("*")).make(ACCOUNT).is_err());
    assert!(team("x", Some("Team-")).make(ACCOUNT).is_err());
    assert!(
        team("Data", None).make(ACCOUNT).unwrap()[0]
            .document
            .contains("arn:aws:s3:::data-*")
    );
    let access = |buckets: &str, levels: Vec<Level>| Use::BucketAccess {
        buckets: buckets.into(),
        levels,
        name: None,
        path: None,
    };
    assert!(access("Bad_Name", vec![Level::Read]).make(ACCOUNT).is_err());
    assert!(access("ok", vec![]).make(ACCOUNT).is_err());
}

#[test]
fn names_bucket_access_by_what_it_allows() {
    let name = |buckets: &str, levels: Vec<Level>| {
        Use::BucketAccess {
            buckets: buckets.into(),
            levels,
            name: None,
            path: None,
        }
        .make(ACCOUNT)
        .unwrap()[0]
            .name
            .clone()
    };
    assert_eq!(name("data", vec![Level::Read]), "data-read");
    assert_eq!(
        name("logs-*", vec![Level::Read, Level::Write]),
        "logs-read-write"
    );
    assert_eq!(name("*", vec![Level::Manage]), "all-buckets-manage");
}

/// The MFA guard denies IAM and the cluster without MFA (access keys too),
/// and nothing with it.
#[test]
fn the_mfa_guard_wants_mfa() {
    use crate::policy::{Context, Decision, Principal, Request};
    let made = Use::MfaGuard {
        name: None,
        path: None,
    }
    .make(ACCOUNT)
    .unwrap();
    let guard = Policy::parse(&made[0].document, Kind::Identity).unwrap();
    let decide = |action: &str, mfa: Option<&str>| {
        let mut context = Context::default();
        if let Some(mfa) = mfa {
            context.set("aws:MultiFactorAuthPresent", mfa);
        }
        let principal = Principal::User {
            account: ACCOUNT,
            name: "u",
            id: "1",
        };
        guard.evaluate(&Request {
            principal,
            action,
            resource: "*",
            context: &context,
        })
    };
    assert_eq!(decide("iam:CreateUser", None), Decision::Deny);
    assert_eq!(decide("cairn:PutSetting", Some("false")), Decision::Deny);
    assert_eq!(
        decide("iam:CreateUser", Some("true")),
        Decision::NotApplicable
    );
    assert_eq!(decide("s3:GetObject", None), Decision::NotApplicable);
}
