//! A bucket's notification configuration (`?notification`), as S3 takes and
//! shows it (probed, see `plans/notifications.md`): topic configurations,
//! each an ID, a topic's ARN, events and a key filter (a prefix and a
//! suffix). Checked in S3's order: each configuration's events, then its
//! filter, then its ID; then IDs across configurations, then overlaps; the
//! destinations last (see `s3::buckets::notification`).

use crate::s3::util::xml_escape;

/// S3's events, in the order S3 lists a configuration's (probed): each
/// group's wildcard first, then its own.
pub const EVENTS: &[&str] = &[
    "s3:ReducedRedundancyLostObject",
    "s3:ObjectCreated:*",
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Post",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectRemoved:*",
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
    "s3:ObjectRestore:*",
    "s3:ObjectRestore:Post",
    "s3:ObjectRestore:Completed",
    "s3:ObjectRestore:Delete",
    "s3:Replication:*",
    "s3:Replication:OperationFailedReplication",
    "s3:Replication:OperationNotTracked",
    "s3:Replication:OperationMissedThreshold",
    "s3:Replication:OperationReplicatedAfterThreshold",
    "s3:ObjectTagging:*",
    "s3:ObjectTagging:Put",
    "s3:ObjectTagging:Delete",
    "s3:ObjectAcl:Put",
    "s3:LifecycleExpiration:*",
    "s3:LifecycleExpiration:Delete",
    "s3:LifecycleExpiration:DeleteMarkerCreated",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
];

/// The most an ID may be (probed).
const MAX_ID: usize = 255;
/// The most a filter rule's value may be, in bytes (probed).
const MAX_VALUE: usize = 1024;

/// One topic configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topic {
    pub id: String,
    pub topic_arn: String,
    /// In S3's order (`EVENTS`).
    pub events: Vec<String>,
    pub prefix: String,
    pub suffix: String,
    /// Whether it has a filter at all.
    pub filtered: bool,
}

/// Why a configuration was refused: S3's code, message and further
/// elements (`ArgumentName`, `ArgumentValue`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub code: &'static str,
    pub message: String,
    pub details: Vec<(&'static str, String)>,
}

fn invalid(message: impl Into<String>, details: Vec<(&'static str, String)>) -> Refused {
    Refused {
        code: "InvalidArgument",
        message: message.into(),
        details,
    }
}

fn malformed() -> Refused {
    Refused {
        code: "MalformedXML",
        message: "The XML you provided was not well-formed or did not validate against our published schema".to_owned(),
        details: Vec::new(),
    }
}

/// What a PUT asked for: its topic configurations, and the destinations
/// Cairn has none of (queues and functions), which fail as S3's
/// destinations it can't validate do; EventBridge is refused outright.
#[derive(Debug, Default)]
pub struct Requested {
    pub topics: Vec<Topic>,
    /// Queues' and functions' ARNs.
    pub elsewhere: Vec<String>,
    pub event_bridge: bool,
}

/// `body` as a configuration, checked as S3 checks it but its destinations.
/// A configuration without an ID gets one (base64 of a UUID's text, as S3's
/// look, and new on every PUT: probed).
pub fn parse(body: &[u8]) -> Result<Requested, Refused> {
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let doc = roxmltree::Document::parse(text).map_err(|_| malformed())?;
    let root = doc.root_element();
    if root.tag_name().name() != "NotificationConfiguration" {
        return Err(malformed());
    }
    let mut requested = Requested::default();
    let child_text = |node: roxmltree::Node, name: &str| {
        node.children()
            .find(|c| c.is_element() && c.tag_name().name() == name)
            .map(|c| c.text().unwrap_or("").to_owned())
    };
    for config in root.children().filter(|c| c.is_element()) {
        match config.tag_name().name() {
            "TopicConfiguration" => {}
            "QueueConfiguration" => {
                requested
                    .elsewhere
                    .push(child_text(config, "Queue").ok_or_else(malformed)?);
                continue;
            }
            "CloudFunctionConfiguration" => {
                requested
                    .elsewhere
                    .push(child_text(config, "CloudFunction").ok_or_else(malformed)?);
                continue;
            }
            "EventBridgeConfiguration" => {
                requested.event_bridge = true;
                continue;
            }
            _ => return Err(malformed()),
        }
        let topic_arn = child_text(config, "Topic").ok_or_else(malformed)?;
        let id = child_text(config, "Id");
        let named: Vec<String> = config
            .children()
            .filter(|c| c.is_element() && c.tag_name().name() == "Event")
            .map(|c| c.text().unwrap_or("").to_owned())
            .collect();
        if named.is_empty() {
            return Err(malformed());
        }
        for event in &named {
            if !EVENTS.contains(&event.as_str()) {
                return Err(invalid(
                    "The event is not supported for notifications",
                    vec![
                        ("ArgumentName", "Event".to_owned()),
                        ("ArgumentValue", event.clone()),
                    ],
                ));
            }
        }
        let (mut prefix, mut suffix, mut filtered) = (None::<String>, None::<String>, false);
        if let Some(filter) = config
            .children()
            .find(|c| c.is_element() && c.tag_name().name() == "Filter")
        {
            filtered = true;
            let rules = filter
                .children()
                .filter(|c| c.is_element() && c.tag_name().name() == "S3Key")
                .flat_map(|key| {
                    key.children()
                        .filter(|c| c.is_element() && c.tag_name().name() == "FilterRule")
                });
            for rule in rules {
                let name = child_text(rule, "Name").unwrap_or_default();
                let value = child_text(rule, "Value").unwrap_or_default();
                let slot = match name.to_ascii_lowercase().as_str() {
                    "prefix" => &mut prefix,
                    "suffix" => &mut suffix,
                    _ => {
                        return Err(invalid(
                            "filter rule name must be either prefix or suffix",
                            vec![
                                ("ArgumentName", "FilterRule.Name".to_owned()),
                                ("ArgumentValue", name),
                            ],
                        ));
                    }
                };
                if slot.is_some() {
                    return Err(invalid(
                        format!(
                            "Cannot specify more than one {} rule in a filter.",
                            name.to_ascii_lowercase()
                        ),
                        vec![("ArgumentName", "FilterRule.Name".to_owned())],
                    ));
                }
                if value.len() > MAX_VALUE {
                    return Err(invalid(
                        "Size of filter rule value cannot exceed 1024 bytes in UTF-8 representation",
                        vec![
                            (
                                "ArgumentName",
                                format!("FilterRule.{}.Value", name.to_ascii_uppercase()),
                            ),
                            ("ArgumentValue", value),
                        ],
                    ));
                }
                *slot = Some(value);
            }
        }
        let id = match id {
            Some(id) if id.chars().count() > MAX_ID => {
                return Err(invalid(
                    format!("ID length exceeded allowed limit of {MAX_ID}"),
                    vec![("ArgumentName", "Id".to_owned()), ("ArgumentValue", id)],
                ));
            }
            Some(id) if !id.is_empty() => id,
            _ => {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(uuid::Uuid::new_v4().to_string())
            }
        };
        requested.topics.push(Topic {
            id,
            topic_arn,
            events: named,
            prefix: prefix.unwrap_or_default(),
            suffix: suffix.unwrap_or_default(),
            filtered,
        });
    }
    // IDs, across configurations.
    for (i, topic) in requested.topics.iter().enumerate() {
        if requested.topics[..i].iter().any(|t| t.id == topic.id) {
            return Err(invalid(
                "Same ID used for multiple configurations. IDs must be unique.",
                vec![
                    ("ArgumentName", "Id".to_owned()),
                    ("ArgumentValue", topic.id.clone()),
                ],
            ));
        }
    }
    check_overlaps(&requested.topics)?;
    for topic in &mut requested.topics {
        topic
            .events
            .sort_by_key(|e| EVENTS.iter().position(|known| known == e));
    }
    Ok(requested)
}

/// Whether two events are, or cover, the same: one's wildcard covers the
/// other.
fn overlap(a: &str, b: &str) -> bool {
    let group = |e: &str| {
        e.rsplit_once(':')
            .map(|(g, _)| g.to_owned())
            .unwrap_or_else(|| e.to_owned())
    };
    a == b
        || (a.ends_with(":*") && group(a) == group(b))
        || (b.ends_with(":*") && group(a) == group(b))
}

/// S3's two overlap errors: a configuration naming an event twice (or its
/// wildcard and itself), or two unfiltered configurations sharing one, is
/// "Configurations overlap"; two whose filters overlap (each prefix a
/// prefix of the other, and each suffix a suffix) for a shared event is
/// "ambiguously defined" (probed).
fn check_overlaps(topics: &[Topic]) -> Result<(), Refused> {
    let overlapping = |pair: String| {
        invalid(
            "Configurations overlap. Configurations on the same bucket cannot share a common event type.",
            vec![
                ("ArgumentName", "Event".to_owned()),
                ("ArgumentValue", pair),
            ],
        )
    };
    for topic in topics {
        for (i, a) in topic.events.iter().enumerate() {
            if let Some(b) = topic.events[i + 1..].iter().find(|b| overlap(a, b)) {
                return Err(overlapping(if a == b {
                    a.clone()
                } else {
                    format!("{a}, {b}")
                }));
            }
        }
    }
    for (i, a) in topics.iter().enumerate() {
        for b in &topics[i + 1..] {
            let Some((ea, eb)) = a.events.iter().find_map(|ea| {
                b.events
                    .iter()
                    .find(|eb| overlap(ea, eb))
                    .map(|eb| (ea, eb))
            }) else {
                continue;
            };
            let prefixes = a.prefix.starts_with(&b.prefix) || b.prefix.starts_with(&a.prefix);
            let suffixes = a.suffix.ends_with(&b.suffix) || b.suffix.ends_with(&a.suffix);
            if !(prefixes && suffixes) {
                continue;
            }
            if !a.filtered && !b.filtered {
                return Err(overlapping(format!("{ea}, {eb}")));
            }
            return Err(invalid(
                "Configuration is ambiguously defined. Cannot have overlapping suffixes in two rules if the prefixes are overlapping for the same event type.",
                vec![("ArgumentName", "FilterRule".to_owned())],
            ));
        }
    }
    Ok(())
}

/// Whether `arn` parses as a topic's: `arn:aws:sns:<region>:<account>:<name>`.
pub fn parse_topic_arn(arn: &str) -> Option<(&str, &str, &str)> {
    let mut parts = arn.splitn(6, ':');
    let (Some("arn"), Some(_partition), Some(service), Some(region), Some(account), Some(name)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    (!service.is_empty() && !name.is_empty())
        .then_some((region, account, name))
        .filter(|_| service == "sns")
}

/// The configuration as GET shows it (probed: no whitespace; `Prefix` before
/// `Suffix`, capitalized).
pub fn xml(topics: &[Topic]) -> String {
    const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
    if topics.is_empty() {
        return format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<NotificationConfiguration xmlns=\"{NS}\"/>"
        );
    }
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<NotificationConfiguration xmlns=\"{NS}\">"
    );
    for t in topics {
        out.push_str(&format!(
            "<TopicConfiguration><Id>{}</Id><Topic>{}</Topic>",
            xml_escape(&t.id),
            xml_escape(&t.topic_arn)
        ));
        for event in &t.events {
            out.push_str(&format!("<Event>{}</Event>", xml_escape(event)));
        }
        if t.filtered {
            out.push_str("<Filter><S3Key>");
            for (name, value) in [("Prefix", &t.prefix), ("Suffix", &t.suffix)] {
                if !value.is_empty() || (name == "Prefix" && t.suffix.is_empty()) {
                    out.push_str(&format!(
                        "<FilterRule><Name>{name}</Name><Value>{}</Value></FilterRule>",
                        xml_escape(value)
                    ));
                }
            }
            out.push_str("</S3Key></Filter>");
        }
        out.push_str("</TopicConfiguration>");
    }
    out.push_str("</NotificationConfiguration>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(inner: &str) -> String {
        format!("<NotificationConfiguration>{inner}</NotificationConfiguration>")
    }

    fn topic(id: &str, events: &[&str], filter: &str) -> String {
        let id = if id.is_empty() {
            String::new()
        } else {
            format!("<Id>{id}</Id>")
        };
        let events: String = events
            .iter()
            .map(|e| format!("<Event>{e}</Event>"))
            .collect();
        format!(
            "<TopicConfiguration>{id}<Topic>arn:aws:sns:us-east-1:123456789012:t</Topic>{events}{filter}</TopicConfiguration>"
        )
    }

    fn rules(rules: &[(&str, &str)]) -> String {
        let rules: String = rules
            .iter()
            .map(|(n, v)| format!("<FilterRule><Name>{n}</Name><Value>{v}</Value></FilterRule>"))
            .collect();
        format!("<Filter><S3Key>{rules}</S3Key></Filter>")
    }

    fn refused(body: &str) -> Refused {
        parse(body.as_bytes()).expect_err("refused")
    }

    #[test]
    fn checks_as_s3_does() {
        // Events first, then filters.
        let r = refused(&config(&topic(
            "",
            &["s3:Bogus"],
            &rules(&[("prefix", "a"), ("prefix", "b")]),
        )));
        assert_eq!(r.message, "The event is not supported for notifications");
        for bad in [
            "s3:*",
            "s3:ObjectCreated",
            "s3:objectcreated:*",
            "ObjectCreated:*",
        ] {
            assert_eq!(refused(&config(&topic("", &[bad], ""))).details[1].1, bad);
        }
        assert_eq!(refused(&config(&topic("", &[], ""))).code, "MalformedXML");
        let r = refused(&config(&topic(
            "",
            &["s3:ObjectCreated:*"],
            &rules(&[("prefix", "a"), ("prefix", "b")]),
        )));
        assert_eq!(
            r.message,
            "Cannot specify more than one prefix rule in a filter."
        );
        let r = refused(&config(&topic(
            "",
            &["s3:ObjectCreated:*"],
            &rules(&[("regex", "a")]),
        )));
        assert_eq!(
            r.message,
            "filter rule name must be either prefix or suffix"
        );
        let long = "p".repeat(1025);
        let r = refused(&config(&topic(
            "",
            &["s3:ObjectCreated:*"],
            &rules(&[("prefix", &long)]),
        )));
        assert_eq!(r.details[0].1, "FilterRule.PREFIX.Value");
        let r = refused(&config(&topic(
            &"i".repeat(256),
            &["s3:ObjectCreated:*"],
            "",
        )));
        assert_eq!(r.message, "ID length exceeded allowed limit of 255");
        // IDs before overlaps.
        let r = refused(&config(
            &(topic("x", &["s3:ObjectCreated:*"], "") + &topic("x", &["s3:ObjectCreated:*"], "")),
        ));
        assert_eq!(
            r.message,
            "Same ID used for multiple configurations. IDs must be unique."
        );
        let r = refused(&config(
            &(topic("", &["s3:ObjectCreated:*"], "") + &topic("", &["s3:ObjectCreated:*"], "")),
        ));
        assert_eq!(r.details[1].1, "s3:ObjectCreated:*, s3:ObjectCreated:*");
        let r = refused(&config(&topic(
            "",
            &["s3:ObjectCreated:*", "s3:ObjectCreated:Put"],
            "",
        )));
        assert_eq!(r.details[1].1, "s3:ObjectCreated:*, s3:ObjectCreated:Put");
        let r = refused(&config(&topic(
            "",
            &["s3:ObjectCreated:Put", "s3:ObjectCreated:Put"],
            "",
        )));
        assert_eq!(r.details[1].1, "s3:ObjectCreated:Put");
        let r = refused(&config(
            &(topic("", &["s3:ObjectCreated:*"], &rules(&[("prefix", "a/")]))
                + &topic("", &["s3:ObjectCreated:Put"], &rules(&[("prefix", "a/b")]))),
        ));
        assert!(
            r.message
                .starts_with("Configuration is ambiguously defined.")
        );
    }

    #[test]
    fn takes_what_s3_takes() {
        let ok = |body: String| parse(body.as_bytes()).expect("taken").topics;
        // Overlapping prefixes for other events, or with other suffixes.
        ok(config(
            &(topic("", &["s3:ObjectCreated:*"], &rules(&[("prefix", "a/")]))
                + &topic("", &["s3:ObjectRemoved:*"], &rules(&[("prefix", "a/")]))),
        ));
        ok(config(
            &(topic(
                "",
                &["s3:ObjectCreated:*"],
                &rules(&[("prefix", "a/"), ("suffix", ".x")]),
            ) + &topic(
                "",
                &["s3:ObjectCreated:*"],
                &rules(&[("prefix", "a/"), ("suffix", ".y")]),
            )),
        ));
        assert!(ok(config("")).is_empty());
        // Any case of a rule's name; events in S3's order; a generated ID.
        let topics = ok(config(&topic(
            "",
            &["s3:ObjectRemoved:*", "s3:ObjectCreated:*"],
            &rules(&[("Suffix", ".txt"), ("PREFIX", "p")]),
        )));
        assert_eq!(
            topics[0].events,
            ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        );
        assert_eq!(
            (topics[0].prefix.as_str(), topics[0].suffix.as_str()),
            ("p", ".txt")
        );
        assert_eq!(topics[0].id.len(), 48);
        let shown = xml(&topics);
        assert!(shown.contains("<Event>s3:ObjectCreated:*</Event><Event>s3:ObjectRemoved:*</Event><Filter><S3Key>\
                                <FilterRule><Name>Prefix</Name><Value>p</Value></FilterRule>\
                                <FilterRule><Name>Suffix</Name><Value>.txt</Value></FilterRule></S3Key></Filter>"));
        assert_eq!(
            xml(&[]),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"
        );
    }

    #[test]
    fn topic_arns() {
        assert_eq!(
            parse_topic_arn("arn:aws:sns:us-east-1:123456789012:t"),
            Some(("us-east-1", "123456789012", "t"))
        );
        assert_eq!(parse_topic_arn("nonsense"), None);
        assert_eq!(
            parse_topic_arn("arn:aws:sqs:us-east-1:123456789012:q"),
            None
        );
    }
}
