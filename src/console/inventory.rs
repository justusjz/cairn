//! The console's API for buckets' S3 Inventory configurations (see
//! `inventory`, `s3::buckets::inventory`): read with their reports' state,
//! and set and deleted through S3's own handlers, as the session's identity,
//! so they're checked as S3 checks them.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};

use super::actor::Actor;
use super::manage::{AppState, Result, s3_error};
use super::web::{ApiError, ErrorBody};
use crate::{
    App,
    db::Cached,
    inventory::{
        LastReport,
        config::{Configuration, Encryption, Field, Frequency},
    },
    policy::Context,
    s3::{actions::On, util::xml_escape},
};

pub(super) fn router() -> OpenApiRouter<Arc<App>> {
    OpenApiRouter::new()
        .routes(routes!(list_inventories))
        .routes(routes!(put_inventory, delete_inventory))
}

/// An inventory configuration, as the console edits it.
#[derive(Serialize, Deserialize, ToSchema)]
struct InventoryForm {
    id: String,
    enabled: bool,
    /// The bucket its reports go to (its name).
    destination_bucket: String,
    /// What's put before the reports' keys, if anything.
    #[serde(default)]
    destination_prefix: String,
    /// The account the destination must be owned by, if it's to be checked.
    #[serde(default)]
    destination_account: Option<String>,
    /// `CSV` or `Parquet`.
    format: String,
    /// `SSE-S3`, or an SSE-KMS key's ARN; none for neither.
    #[serde(default)]
    encryption: Option<String>,
    /// Only keys with this prefix (empty: all).
    #[serde(default)]
    prefix: String,
    /// Every version and delete marker, or only the current objects.
    all_versions: bool,
    /// `Daily` or `Weekly`.
    frequency: String,
    /// Optional fields (S3's names: `Size`, `ETag`, ...).
    #[serde(default)]
    fields: Vec<String>,
}

/// A configuration, and how its reports are going.
#[derive(Serialize, ToSchema)]
struct Inventory {
    configuration: InventoryForm,
    /// When its next report is due (seconds since the epoch).
    due: f64,
    /// When the report in progress started, if one is.
    started: Option<f64>,
    /// Versions the report in progress read, and data files it wrote.
    seen: i64,
    files: i32,
    /// Its last failure, and when, if it failed since its last report.
    failure: Option<String>,
    failed_at: Option<f64>,
    /// Its last whole report, if it made one.
    last: Option<LastInventory>,
}

#[derive(Serialize, ToSchema)]
struct LastInventory {
    started: f64,
    finished: f64,
    read: i64,
    files: i32,
    /// Its manifest's key, in the destination bucket.
    manifest: String,
}

#[derive(Serialize, ToSchema)]
struct BucketInventories {
    inventories: Vec<Inventory>,
    /// The optional fields a configuration may ask for.
    fields: Vec<String>,
}

fn form_of(c: Configuration) -> InventoryForm {
    InventoryForm {
        id: c.id,
        enabled: c.enabled,
        destination_bucket: c.destination.bucket,
        destination_prefix: c.destination.prefix.unwrap_or_default(),
        destination_account: c.destination.account,
        format: c.destination.format.name().to_owned(),
        encryption: c.destination.encryption.map(|e| match e {
            Encryption::S3 => "SSE-S3".to_owned(),
            Encryption::Kms(id) => id.clone(),
        }),
        prefix: c.prefix.unwrap_or_default(),
        all_versions: c.all_versions,
        frequency: match c.frequency {
            Frequency::Daily => "Daily",
            Frequency::Weekly => "Weekly",
        }
        .to_owned(),
        fields: c.fields.iter().map(|f| f.name().to_owned()).collect(),
    }
}

/// A bucket's inventory configurations, by their IDs, and their reports.
#[utoipa::path(get, path = "/buckets/{bucket}/inventory", params(("bucket" = String, Path)), responses(
    (status = 200, body = BucketInventories),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn list_inventories(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path(bucket): Path<String>,
) -> Result<Json<BucketInventories>> {
    actor
        .check(
            &app,
            "s3:GetInventoryConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let client = app.pool.get().await?;
    if client
        .query_opt_cached("SELECT 1 FROM buckets WHERE name = $1", &[&bucket])
        .await?
        .is_none()
    {
        return Err(ApiError::NotFound(format!("no bucket named {bucket:?}")));
    }
    let rows = client
        .query_cached(
            "SELECT config, extract(epoch FROM due)::float8, extract(epoch FROM started)::float8, seen, files, failure,
                    extract(epoch FROM failed_at)::float8, last
             FROM inventories WHERE bucket = $1 ORDER BY id",
            &[&bucket],
        )
        .await?;
    let mut inventories = Vec::new();
    for row in rows {
        let config = Configuration::from_json(row.get(0)).map_err(anyhow::Error::from)?;
        let last = row
            .get::<_, Option<&str>>(7)
            .and_then(|l| serde_json::from_str::<LastReport>(l).ok())
            .map(|l| LastInventory {
                started: l.started,
                finished: l.finished,
                read: l.read,
                files: l.files,
                manifest: l.manifest,
            });
        inventories.push(Inventory {
            configuration: form_of(config),
            due: row.get(1),
            started: row.get(2),
            seen: row.get(3),
            files: row.get(4),
            failure: row.get(5),
            failed_at: row.get(6),
            last,
        });
    }
    Ok(Json(BucketInventories {
        inventories,
        fields: Field::ALL.iter().map(|f| f.name().to_owned()).collect(),
    }))
}

/// The form as S3's PutBucketInventoryConfiguration takes it.
fn xml_of(f: &InventoryForm) -> String {
    let mut destination = String::new();
    if let Some(account) = f.destination_account.as_ref().filter(|a| !a.is_empty()) {
        destination.push_str(&format!("<AccountId>{}</AccountId>", xml_escape(account)));
    }
    destination.push_str(&format!(
        "<Bucket>arn:aws:s3:::{}</Bucket>",
        xml_escape(&f.destination_bucket)
    ));
    destination.push_str(&format!("<Format>{}</Format>", xml_escape(&f.format)));
    if !f.destination_prefix.is_empty() {
        destination.push_str(&format!(
            "<Prefix>{}</Prefix>",
            xml_escape(&f.destination_prefix)
        ));
    }
    match f.encryption.as_deref() {
        None | Some("") => {}
        Some("SSE-S3") => destination.push_str("<Encryption><SSE-S3/></Encryption>"),
        Some(key) => destination.push_str(&format!(
            "<Encryption><SSE-KMS><KeyId>{}</KeyId></SSE-KMS></Encryption>",
            xml_escape(key)
        )),
    }
    let mut xml = format!(
        "<InventoryConfiguration><Id>{}</Id><IsEnabled>{}</IsEnabled><Destination><S3BucketDestination>{destination}\
         </S3BucketDestination></Destination>",
        xml_escape(&f.id),
        f.enabled
    );
    if !f.prefix.is_empty() {
        xml.push_str(&format!(
            "<Filter><Prefix>{}</Prefix></Filter>",
            xml_escape(&f.prefix)
        ));
    }
    xml.push_str(&format!(
        "<IncludedObjectVersions>{}</IncludedObjectVersions>",
        if f.all_versions { "All" } else { "Current" }
    ));
    if !f.fields.is_empty() {
        let fields: String = f
            .fields
            .iter()
            .map(|n| format!("<Field>{}</Field>", xml_escape(n)))
            .collect();
        xml.push_str(&format!("<OptionalFields>{fields}</OptionalFields>"));
    }
    xml.push_str(&format!(
        "<Schedule><Frequency>{}</Frequency></Schedule></InventoryConfiguration>",
        xml_escape(&f.frequency)
    ));
    xml
}

/// Sets an inventory configuration, as S3's PutBucketInventoryConfiguration
/// does: its reports go to the destination as S3 writes them, so the
/// destination's policy must allow `s3.amazonaws.com` to write them.
#[utoipa::path(put, path = "/buckets/{bucket}/inventory/{id}", params(("bucket" = String, Path), ("id" = String, Path)),
    request_body = InventoryForm, responses(
        (status = 204, description = "Set"),
        (status = "4XX", body = ErrorBody),
        (status = "5XX", body = ErrorBody),
    ))]
async fn put_inventory(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((bucket, id)): Path<(String, String)>,
    Json(form): Json<InventoryForm>,
) -> Result<StatusCode> {
    let mut context = Context::default();
    context.set_all("s3:InventoryAccessibleOptionalFields", form.fields.clone());
    actor
        .check_with(
            &app,
            "s3:PutInventoryConfiguration",
            On::Bucket(bucket.clone()),
            &context,
        )
        .await?;
    let query = format!(
        "inventory&id={}",
        percent_encoding::utf8_percent_encode(&id, percent_encoding::NON_ALPHANUMERIC)
    );
    let response = crate::s3::buckets::inventory::put(
        &app,
        &bucket,
        &query,
        xml_of(&form).into(),
        actor.user_id(),
    )
    .await?;
    if !response.status().is_success() {
        return Err(s3_error(response).await);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Deletes an inventory configuration; a report of it in progress stops.
#[utoipa::path(delete, path = "/buckets/{bucket}/inventory/{id}", params(("bucket" = String, Path), ("id" = String, Path)), responses(
    (status = 204, description = "Deleted"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_inventory(
    State(app): AppState,
    Extension(actor): Extension<Actor>,
    Path((bucket, id)): Path<(String, String)>,
) -> Result<StatusCode> {
    // DeleteBucketInventoryConfiguration is authorized as its put, in S3.
    actor
        .check(
            &app,
            "s3:PutInventoryConfiguration",
            On::Bucket(bucket.clone()),
        )
        .await?;
    let query = format!(
        "inventory&id={}",
        percent_encoding::utf8_percent_encode(&id, percent_encoding::NON_ALPHANUMERIC)
    );
    let response = crate::s3::buckets::inventory::delete(&app, &bucket, &query).await?;
    if !response.status().is_success() {
        return Err(s3_error(response).await);
    }
    Ok(StatusCode::NO_CONTENT)
}
