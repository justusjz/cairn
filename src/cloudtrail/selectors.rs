//! A trail's event selectors: which events it delivers, as
//! `PutEventSelectors` sets them, either CloudTrail's basic ones
//! (`EventSelectors`: management events, read, written or both, but those
//! of the services they exclude) or its advanced ones
//! (`AdvancedEventSelectors`: conditions on an event's fields).
//!
//! Every event Cairn records is a management event: a selector of data
//! events (S3's object-level calls, ...) is kept and given back, as
//! CloudTrail's is, but matches nothing yet.

use serde_json::{Map, Value, json};

/// The most basic selectors a trail may have.
const MAX_BASIC: usize = 5;
/// The most data resources a trail's basic selectors may name, together.
const MAX_DATA_VALUES: usize = 250;
/// The most conditions a trail's advanced selectors may have, together.
const MAX_CONDITIONS: usize = 500;
/// The services whose management events a basic selector may exclude.
const EXCLUDABLE: &[&str] = &["kms.amazonaws.com", "rdsdata.amazonaws.com"];
/// The kinds of data resources a basic selector may name.
const DATA_TYPES: &[&str] = &[
    "AWS::S3::Object",
    "AWS::Lambda::Function",
    "AWS::DynamoDB::Table",
];
/// The fields an advanced selector may have conditions on.
const FIELDS: &[&str] = &[
    "eventCategory",
    "eventSource",
    "eventName",
    "eventType",
    "readOnly",
    "resources.type",
    "resources.ARN",
    "errorCode",
    "userIdentity.arn",
    "sessionCredentialFromConsole",
    "vpcEndpointId",
];
/// The event categories an advanced selector may select.
const CATEGORIES: &[&str] = &["Management", "Data", "NetworkActivity", "ConfigurationItem"];

/// Why selectors aren't valid (`InvalidEventSelectorsException`).
#[derive(Debug, PartialEq)]
pub struct Invalid(pub String);

fn invalid<T>(message: impl Into<String>) -> Result<T, Invalid> {
    Err(Invalid(message.into()))
}

/// A basic selector's `ReadWriteType`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ReadWrite {
    ReadOnly,
    WriteOnly,
    All,
}

impl ReadWrite {
    fn as_str(self) -> &'static str {
        match self {
            ReadWrite::ReadOnly => "ReadOnly",
            ReadWrite::WriteOnly => "WriteOnly",
            ReadWrite::All => "All",
        }
    }
}

/// A basic selector.
#[derive(Clone, Debug, PartialEq)]
pub struct Basic {
    read_write: ReadWrite,
    management: bool,
    /// The services whose management events it leaves out.
    exclude: Vec<String>,
    /// Its data resources, as given (`[{Type, Values}]`).
    data: Vec<Value>,
}

/// An advanced selector's conditions on a field.
#[derive(Clone, Debug, PartialEq)]
struct Field {
    field: String,
    /// Its operators (`Equals`, `NotStartsWith`, ...), and their values.
    operators: Vec<(&'static str, Vec<String>)>,
}

/// The operators a field's condition may have: those that must match one
/// of their values, and those that must match none.
const OPERATORS: &[(&str, bool)] = &[
    ("Equals", true),
    ("StartsWith", true),
    ("EndsWith", true),
    ("NotEquals", false),
    ("NotStartsWith", false),
    ("NotEndsWith", false),
];

/// An advanced selector.
#[derive(Clone, Debug, PartialEq)]
pub struct Advanced {
    name: Option<String>,
    fields: Vec<Field>,
}

/// A trail's selectors.
#[derive(Clone, Debug, PartialEq)]
pub enum Selectors {
    Basic(Vec<Basic>),
    Advanced(Vec<Advanced>),
}

impl Default for Selectors {
    /// A new trail's: every management event.
    fn default() -> Selectors {
        Selectors::Basic(vec![Basic {
            read_write: ReadWrite::All,
            management: true,
            exclude: Vec::new(),
            data: Vec::new(),
        }])
    }
}

/// `value` as a list of strings, if it's one.
fn strings(value: &Value, what: &str) -> Result<Vec<String>, Invalid> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|i| {
                i.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Invalid(format!("{what} must be a list of strings")))
            })
            .collect(),
        _ => invalid(format!("{what} must be a list of strings")),
    }
}

impl Selectors {
    /// A `PutEventSelectors`' (or the database's) `EventSelectors` or
    /// `AdvancedEventSelectors`: exactly one of them.
    pub fn parse(params: &Map<String, Value>) -> Result<Selectors, Invalid> {
        let given = |name: &str| params.get(name).filter(|v| !v.is_null());
        match (given("EventSelectors"), given("AdvancedEventSelectors")) {
            (Some(_), Some(_)) => {
                invalid("Specify either EventSelectors or AdvancedEventSelectors, not both")
            }
            (None, None) => invalid("Specify EventSelectors or AdvancedEventSelectors"),
            (Some(basic), None) => Self::parse_basic(basic),
            (None, Some(advanced)) => Self::parse_advanced(advanced),
        }
    }

    fn parse_basic(value: &Value) -> Result<Selectors, Invalid> {
        let Some(items) = value.as_array() else {
            return invalid("EventSelectors must be a list");
        };
        if items.len() > MAX_BASIC {
            return invalid(format!(
                "A trail may have at most {MAX_BASIC} event selectors"
            ));
        }
        let mut selectors = Vec::new();
        let mut data_values = 0;
        for item in items {
            let Some(item) = item.as_object() else {
                return invalid("An event selector must be an object");
            };
            let read_write = match item.get("ReadWriteType").and_then(Value::as_str) {
                None => ReadWrite::All,
                Some("ReadOnly") => ReadWrite::ReadOnly,
                Some("WriteOnly") => ReadWrite::WriteOnly,
                Some("All") => ReadWrite::All,
                Some(other) => {
                    return invalid(format!(
                        "{other} isn't a ReadWriteType: ReadOnly, WriteOnly or All"
                    ));
                }
            };
            let management = match item.get("IncludeManagementEvents") {
                None | Some(Value::Null) => true,
                Some(Value::Bool(b)) => *b,
                Some(_) => return invalid("IncludeManagementEvents must be true or false"),
            };
            let exclude = strings(
                item.get("ExcludeManagementEventSources")
                    .unwrap_or(&Value::Null),
                "ExcludeManagementEventSources",
            )?;
            if let Some(other) = exclude.iter().find(|s| !EXCLUDABLE.contains(&s.as_str())) {
                return invalid(format!(
                    "{other} can't be excluded: only {} can",
                    EXCLUDABLE.join(" and ")
                ));
            }
            let mut data = Vec::new();
            match item.get("DataResources") {
                None | Some(Value::Null) => {}
                Some(Value::Array(resources)) => {
                    for resource in resources {
                        let kind = resource["Type"].as_str().unwrap_or("");
                        if !DATA_TYPES.contains(&kind) {
                            return invalid(format!(
                                "{kind:?} isn't a data resource's type: one of {}",
                                DATA_TYPES.join(", ")
                            ));
                        }
                        let values = strings(&resource["Values"], "A data resource's Values")?;
                        data_values += values.len();
                        data.push(json!({ "Type": kind, "Values": values }));
                    }
                }
                Some(_) => return invalid("DataResources must be a list"),
            }
            selectors.push(Basic {
                read_write,
                management,
                exclude,
                data,
            });
        }
        if data_values > MAX_DATA_VALUES {
            return invalid(format!(
                "A trail's event selectors may name at most {MAX_DATA_VALUES} data resources"
            ));
        }
        Ok(Selectors::Basic(selectors))
    }

    fn parse_advanced(value: &Value) -> Result<Selectors, Invalid> {
        let Some(items) = value.as_array() else {
            return invalid("AdvancedEventSelectors must be a list");
        };
        let mut selectors = Vec::new();
        let mut conditions = 0;
        for item in items {
            let name = match item.get("Name") {
                None | Some(Value::Null) => None,
                Some(Value::String(name)) if name.chars().count() <= 1000 => Some(name.clone()),
                Some(_) => {
                    return invalid("An advanced event selector's Name is 0 to 1000 characters");
                }
            };
            let Some(given) = item.get("FieldSelectors").and_then(Value::as_array) else {
                return invalid("An advanced event selector must have FieldSelectors");
            };
            if given.is_empty() {
                return invalid("An advanced event selector must have FieldSelectors");
            }
            let mut fields = Vec::new();
            for field in given {
                let Some(name) = field["Field"].as_str() else {
                    return invalid("A field selector must name its Field");
                };
                if !FIELDS.contains(&name) {
                    return invalid(format!(
                        "{name} isn't a field an advanced event selector may select on: one of {}",
                        FIELDS.join(", ")
                    ));
                }
                if fields.iter().any(|f: &Field| f.field == name) {
                    return invalid(format!("An advanced event selector has {name} twice"));
                }
                let mut operators = Vec::new();
                for (operator, _) in OPERATORS {
                    let values = strings(
                        field.get(*operator).unwrap_or(&Value::Null),
                        &format!("{name}'s {operator}"),
                    )?;
                    if let Some(value) = values.iter().find(|v| v.is_empty() || v.len() > 2048) {
                        return invalid(format!(
                            "{name}'s {operator} has {value:?}: values are 1 to 2048 characters"
                        ));
                    }
                    if !values.is_empty() {
                        conditions += values.len();
                        operators.push((*operator, values));
                    }
                }
                if operators.is_empty() {
                    return invalid(format!("The field selector of {name} has no condition"));
                }
                fields.push(Field {
                    field: name.to_owned(),
                    operators,
                });
            }
            // Each selects a category of events, as CloudTrail requires.
            let category = fields.iter().find(|f| f.field == "eventCategory");
            let Some(category) = category else {
                return invalid("An advanced event selector must select an eventCategory");
            };
            if category.operators.len() != 1 || category.operators[0].0 != "Equals" {
                return invalid("eventCategory's condition must be Equals");
            }
            if let Some(other) = category.operators[0]
                .1
                .iter()
                .find(|c| !CATEGORIES.contains(&c.as_str()))
            {
                return invalid(format!(
                    "{other} isn't an event category: one of {}",
                    CATEGORIES.join(", ")
                ));
            }
            selectors.push(Advanced { name, fields });
        }
        if conditions > MAX_CONDITIONS {
            return invalid(format!(
                "A trail's advanced event selectors may have at most {MAX_CONDITIONS} conditions"
            ));
        }
        Ok(Selectors::Advanced(selectors))
    }

    /// As `GetEventSelectors` answers, and the database keeps them: the
    /// member `EventSelectors` or `AdvancedEventSelectors`.
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        match self {
            Selectors::Basic(selectors) => {
                let items = selectors
                    .iter()
                    .map(|s| {
                        json!({
                            "ReadWriteType": s.read_write.as_str(),
                            "IncludeManagementEvents": s.management,
                            "DataResources": s.data,
                            "ExcludeManagementEventSources": s.exclude,
                        })
                    })
                    .collect();
                out.insert("EventSelectors".to_owned(), Value::Array(items));
            }
            Selectors::Advanced(selectors) => {
                let items = selectors
                    .iter()
                    .map(|s| {
                        let fields: Vec<Value> = s
                            .fields
                            .iter()
                            .map(|f| {
                                let mut field = Map::new();
                                field.insert("Field".to_owned(), json!(f.field));
                                for (operator, values) in &f.operators {
                                    field.insert((*operator).to_owned(), json!(values));
                                }
                                Value::Object(field)
                            })
                            .collect();
                        let mut selector = json!({ "FieldSelectors": fields });
                        if let Some(name) = &s.name {
                            selector["Name"] = json!(name);
                        }
                        selector
                    })
                    .collect();
                out.insert("AdvancedEventSelectors".to_owned(), Value::Array(items));
            }
        }
        out
    }

    /// Whether the trail delivers `record` (CloudTrail's record of an
    /// event): if any of its selectors selects it.
    pub fn select(&self, record: &Value) -> bool {
        let management = record["managementEvent"].as_bool().unwrap_or(true);
        match self {
            Selectors::Basic(selectors) => management && selectors.iter().any(|s| s.select(record)),
            Selectors::Advanced(selectors) => selectors.iter().any(|s| s.select(record)),
        }
    }
}

impl Basic {
    fn select(&self, record: &Value) -> bool {
        let read_only = record["readOnly"].as_bool().unwrap_or(false);
        let source = record["eventSource"].as_str().unwrap_or("");
        self.management
            && match self.read_write {
                ReadWrite::ReadOnly => read_only,
                ReadWrite::WriteOnly => !read_only,
                ReadWrite::All => true,
            }
            && !self.exclude.iter().any(|s| s == source)
    }
}

impl Advanced {
    fn select(&self, record: &Value) -> bool {
        self.fields.iter().all(|f| f.select(record))
    }
}

impl Field {
    /// What `record` has for the field: its values (several for a
    /// resource's, one per resource).
    fn values(&self, record: &Value) -> Vec<String> {
        let text = |v: &Value| match v {
            Value::String(s) => Some(s.clone()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Null => None,
            other => Some(other.to_string()),
        };
        let resources = || record["resources"].as_array().into_iter().flatten();
        match self.field.as_str() {
            "eventCategory" => vec![
                record["eventCategory"]
                    .as_str()
                    .unwrap_or("Management")
                    .to_owned(),
            ],
            "resources.type" => resources().filter_map(|r| text(&r["type"])).collect(),
            "resources.ARN" => resources().filter_map(|r| text(&r["ARN"])).collect(),
            "userIdentity.arn" => text(&record["userIdentity"]["arn"]).into_iter().collect(),
            "sessionCredentialFromConsole" => {
                vec![text(&record["sessionCredentialFromConsole"]).unwrap_or("false".to_owned())]
            }
            field => text(&record[field]).into_iter().collect(),
        }
    }

    /// Whether `record` meets the conditions: one of the values of each
    /// operator that must match one, none of those that must match none.
    fn select(&self, record: &Value) -> bool {
        let have = self.values(record);
        self.operators.iter().all(|(operator, values)| {
            let positive = OPERATORS
                .iter()
                .any(|(o, positive)| o == operator && *positive);
            let test = |have: &str, value: &str| match *operator {
                "Equals" | "NotEquals" => have == value,
                "StartsWith" | "NotStartsWith" => have.starts_with(value),
                _ => have.ends_with(value),
            };
            let any = have.iter().any(|h| values.iter().any(|v| test(h, v)));
            if positive { any } else { !any }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(value: Value) -> Result<Selectors, Invalid> {
        let Value::Object(params) = value else {
            unreachable!()
        };
        Selectors::parse(&params)
    }

    fn record(source: &str, name: &str, read_only: bool) -> Value {
        let resources = match source {
            "kms.amazonaws.com" => {
                json!([{ "type": "AWS::KMS::Key", "ARN": "arn:aws:kms:r:1:key/k" }])
            }
            _ => json!([]),
        };
        json!({
            "eventSource": source,
            "eventName": name,
            "readOnly": read_only,
            "managementEvent": true,
            "eventCategory": "Management",
            "resources": resources,
        })
    }

    #[test]
    fn basic_selectors_select() {
        let decrypt = record("kms.amazonaws.com", "Decrypt", true);
        let create = record("kms.amazonaws.com", "CreateKey", false);
        let lookup = record("cloudtrail.amazonaws.com", "LookupEvents", true);
        let all = Selectors::default();
        assert!(all.select(&decrypt) && all.select(&create) && all.select(&lookup));

        let writes =
            parse(json!({ "EventSelectors": [{ "ReadWriteType": "WriteOnly" }] })).unwrap();
        assert!(!writes.select(&decrypt) && writes.select(&create));

        let no_kms = parse(json!({ "EventSelectors": [{
            "ExcludeManagementEventSources": ["kms.amazonaws.com"],
        }] }))
        .unwrap();
        assert!(!no_kms.select(&decrypt) && no_kms.select(&lookup));

        let none =
            parse(json!({ "EventSelectors": [{ "IncludeManagementEvents": false }] })).unwrap();
        assert!(!none.select(&create));
        let empty = parse(json!({ "EventSelectors": [] })).unwrap();
        assert!(!empty.select(&create));

        // As given back: with every member, its defaults filled in.
        assert_eq!(
            Value::Object(writes.to_json()),
            json!({ "EventSelectors": [{
                "ReadWriteType": "WriteOnly",
                "IncludeManagementEvents": true,
                "DataResources": [],
                "ExcludeManagementEventSources": [],
            }] })
        );
        assert_eq!(parse(Value::Object(writes.to_json())).unwrap(), writes);
    }

    #[test]
    fn advanced_selectors_select() {
        let decrypt = record("kms.amazonaws.com", "Decrypt", true);
        let create = record("kms.amazonaws.com", "CreateKey", false);
        let lookup = record("cloudtrail.amazonaws.com", "LookupEvents", true);
        let selectors = parse(json!({ "AdvancedEventSelectors": [
            {
                "Name": "writes, but KMS's",
                "FieldSelectors": [
                    { "Field": "eventCategory", "Equals": ["Management"] },
                    { "Field": "readOnly", "Equals": ["false"] },
                    { "Field": "eventSource", "NotEquals": ["kms.amazonaws.com"] },
                ],
            },
            {
                "FieldSelectors": [
                    { "Field": "eventCategory", "Equals": ["Management"] },
                    { "Field": "eventName", "StartsWith": ["Look"] },
                ],
            },
        ] }))
        .unwrap();
        assert!(!selectors.select(&decrypt));
        assert!(!selectors.select(&create));
        assert!(selectors.select(&lookup));

        let by_resource = parse(json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
            { "Field": "eventCategory", "Equals": ["Management"] },
            { "Field": "resources.ARN", "EndsWith": [":key/k"] },
        ] }] }))
        .unwrap();
        assert!(by_resource.select(&decrypt) && !by_resource.select(&lookup));

        // Data events: kept, but there are none.
        let data = parse(json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
            { "Field": "eventCategory", "Equals": ["Data"] },
            { "Field": "resources.type", "Equals": ["AWS::S3::Object"] },
        ] }] }))
        .unwrap();
        assert!(!data.select(&decrypt));
        assert_eq!(parse(Value::Object(data.to_json())).unwrap(), data);
    }

    #[test]
    fn invalid_selectors_are_refused() {
        for params in [
            json!({}),
            json!({ "EventSelectors": [], "AdvancedEventSelectors": [] }),
            json!({ "EventSelectors": [{ "ReadWriteType": "Sometimes" }] }),
            json!({ "EventSelectors": [{ "ExcludeManagementEventSources": ["s3.amazonaws.com"] }] }),
            json!({ "EventSelectors": [{ "DataResources": [{ "Type": "AWS::Foo", "Values": [] }] }] }),
            json!({ "EventSelectors": [{}, {}, {}, {}, {}, {}] }),
            json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [] }] }),
            json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
                { "Field": "readOnly", "Equals": ["true"] },
            ] }] }),
            json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
                { "Field": "eventCategory", "Equals": ["Insight"] },
            ] }] }),
            json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
                { "Field": "eventCategory", "Equals": ["Management"] },
                { "Field": "color", "Equals": ["red"] },
            ] }] }),
            json!({ "AdvancedEventSelectors": [{ "FieldSelectors": [
                { "Field": "eventCategory", "Equals": ["Management"] },
                { "Field": "readOnly" },
            ] }] }),
        ] {
            assert!(parse(params.clone()).is_err(), "{params}");
        }
    }
}
