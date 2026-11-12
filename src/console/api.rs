//! The console's JSON API, under `/api`: signing in with a passkey (and the
//! first through an enrollment link), signing out, and the signed-in user's
//! own passkeys. Its OpenAPI spec is committed as `ui/console-openapi.json`,
//! which the console UI's types are generated from.
//!
//! The ceremonies take two requests each: the options (with a challenge,
//! kept in the database for five minutes, and used once), which the page
//! hands `navigator.credentials`, and the browser's response, which the
//! server checks (`webauthn`). Binary values travel as unpadded base64url,
//! as in WebAuthn's own JSON forms.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{Console, Signed, cleared_cookie, session_cookie, session_token, store, webauthn};
use crate::dashboard::{ApiError, ErrorBody};

type Result<T> = std::result::Result<T, ApiError>;
type ConsoleState = State<Arc<Console>>;

#[derive(OpenApi)]
#[openapi(
    info(title = "Cairn console API", description = "The API of Cairn's console."),
    servers((url = "/api")),
    components(schemas(ErrorBody))
)]
struct Doc;

pub(super) fn router() -> OpenApiRouter<Arc<Console>> {
    OpenApiRouter::with_openapi(Doc::openapi())
        .routes(routes!(enroll_options))
        .routes(routes!(enroll))
        .routes(routes!(login_options))
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(me))
        .routes(routes!(passkey_options))
        .routes(routes!(add_passkey))
        .routes(routes!(rename_passkey, delete_passkey))
}

/// The API's OpenAPI spec, as committed in `ui/console-openapi.json`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    router().split_for_parts().1
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str, what: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| ApiError::BadRequest(format!("{what} isn't base64url")))
}

fn refused(e: webauthn::Refused) -> ApiError {
    ApiError::BadRequest(format!("the passkey's response was refused: {}", e.0))
}

// ─── Options ─────────────────────────────────────────────────────────────────

/// A ceremony's options, for `navigator.credentials` (WebAuthn's JSON form:
/// `PublicKeyCredentialCreationOptionsJSON` or `…RequestOptionsJSON`), and
/// the ID of its challenge, to send back with the response.
#[derive(Serialize, ToSchema)]
struct Ceremony {
    challenge_id: String,
    #[schema(value_type = Object)]
    options: Value,
}

/// Options to register a passkey for `user`, not on an authenticator that
/// has one of `existing` already.
fn creation_options(console: &Console, user: &store::User, challenge: &[u8], existing: &[Vec<u8>]) -> Value {
    json!({
        "rp": { "id": console.party.id, "name": "Cairn" },
        "user": { "id": b64(user.id.as_bytes()), "name": user.name, "displayName": user.name },
        "challenge": b64(challenge),
        "pubKeyCredParams": webauthn::ALGORITHMS.iter().map(|alg| json!({ "type": "public-key", "alg": alg })).collect::<Vec<_>>(),
        "timeout": store::CHALLENGE_TTL.as_millis() as u64,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "excludeCredentials": existing.iter().map(|id| json!({ "type": "public-key", "id": b64(id) })).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize, ToSchema)]
struct Enrollment {
    /// The token of the enrollment link (after its `#`).
    token: String,
}

/// The options to register a user's first passkey, through an enrollment
/// link, and whose it'll be.
#[derive(Serialize, ToSchema)]
struct EnrollCeremony {
    user: String,
    #[serde(flatten)]
    ceremony: Ceremony,
}

#[utoipa::path(post, path = "/enroll/options", request_body = Enrollment, responses(
    (status = 200, body = EnrollCeremony),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enroll_options(State(console): ConsoleState, Json(body): Json<Enrollment>) -> Result<Json<EnrollCeremony>> {
    let client = console.app.pool.get().await?;
    let Some(user) = store::enrollment(&client, &body.token).await? else {
        return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into()));
    };
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Enroll, Some(user.id)).await?;
    let existing = store::credential_ids(&client, user.id).await?;
    let options = creation_options(&console, &user, &challenge, &existing);
    Ok(Json(EnrollCeremony { user: user.name, ceremony: Ceremony { challenge_id: id.to_string(), options } }))
}

#[utoipa::path(post, path = "/login/options", responses(
    (status = 200, body = Ceremony),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn login_options(State(console): ConsoleState) -> Result<Json<Ceremony>> {
    let client = console.app.pool.get().await?;
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Login, None).await?;
    // No credentials listed: the authenticator offers the passkeys it has
    // for the console, and says whose the chosen one is.
    let options = json!({
        "challenge": b64(&challenge),
        "rpId": console.party.id,
        "timeout": store::CHALLENGE_TTL.as_millis() as u64,
        "userVerification": "required",
        "allowCredentials": [],
    });
    Ok(Json(Ceremony { challenge_id: id.to_string(), options }))
}

#[utoipa::path(post, path = "/passkeys/options", responses(
    (status = 200, body = Ceremony),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn passkey_options(State(console): ConsoleState, signed: Signed) -> Result<Json<Ceremony>> {
    let client = console.app.pool.get().await?;
    let user = signed.session.user;
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Add, Some(user.id)).await?;
    let existing = store::credential_ids(&client, user.id).await?;
    let options = creation_options(&console, &user, &challenge, &existing);
    Ok(Json(Ceremony { challenge_id: id.to_string(), options }))
}

// ─── Responses ───────────────────────────────────────────────────────────────

/// What `navigator.credentials.create()` gave the page (its parts, in
/// base64url).
#[derive(Deserialize, ToSchema)]
struct Registration {
    id: String,
    client_data_json: String,
    attestation_object: String,
}

/// What `navigator.credentials.get()` gave the page.
#[derive(Deserialize, ToSchema)]
struct Assertion {
    id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    /// The user the passkey is of, as the authenticator says.
    user_handle: Option<String>,
}

/// Takes challenge `id` for `purpose`: its bytes, and whose it is.
async fn take_challenge(
    client: &deadpool_postgres::Object,
    id: &str,
    purpose: store::Purpose,
) -> Result<(Vec<u8>, Option<Uuid>)> {
    let expired = || ApiError::BadRequest("this sign-in took too long, or was used already; try again".into());
    let id: Uuid = id.parse().map_err(|_| expired())?;
    store::take_challenge(client, id, purpose).await?.ok_or_else(expired)
}

/// Checks a registration against its challenge, and adds the passkey it
/// made to `user`: through `enrollment`, or signed in.
async fn register(
    console: &Console,
    client: &deadpool_postgres::Object,
    user: Uuid,
    enrollment: Option<&str>,
    challenge: &[u8],
    name: &str,
    registration: &Registration,
) -> Result<Vec<u8>> {
    let name = store::check_name(name)?;
    let client_data = unb64(&registration.client_data_json, "client_data_json")?;
    let attestation = unb64(&registration.attestation_object, "attestation_object")?;
    let credential = webauthn::verify_registration(&console.party, challenge, &client_data, &attestation).map_err(refused)?;
    if unb64(&registration.id, "id")? != credential.id {
        return Err(ApiError::BadRequest("the credential's ID isn't the one it was registered with".into()));
    }
    let key = store::NewPasskey {
        credential_id: &credential.id,
        public_key: &credential.public_key,
        sign_count: credential.sign_count,
        name,
        backup_eligible: credential.backup_eligible,
        backed_up: credential.backed_up,
    };
    store::add_passkey(client, user, enrollment, &key).await?;
    Ok(credential.id)
}

#[derive(Deserialize, ToSchema)]
struct NewPasskey {
    challenge_id: String,
    /// What to call it, e.g. "Laptop".
    name: String,
    credential: Registration,
}

#[derive(Deserialize, ToSchema)]
struct Enroll {
    token: String,
    #[serde(flatten)]
    passkey: NewPasskey,
}

/// Registers a user's first passkey through its enrollment link (which it
/// uses up), and signs in with it.
#[utoipa::path(post, path = "/enroll", request_body = Enroll, responses(
    (status = 200, body = Me, description = "Signed in; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enroll(State(console): ConsoleState, Json(body): Json<Enroll>) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let (challenge, owner) = take_challenge(&client, &body.passkey.challenge_id, store::Purpose::Enroll).await?;
    let Some(user) = store::enrollment(&client, &body.token).await? else {
        return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into()));
    };
    if owner != Some(user.id) {
        return Err(ApiError::BadRequest("this challenge isn't this enrollment link's".into()));
    }
    let p = &body.passkey;
    let credential = register(&console, &client, user.id, Some(&body.token), &challenge, &p.name, &p.credential).await?;
    signed_in(&client, user, &credential).await
}

/// Starts a session for `user`, signed in with `credential`: the response
/// with its cookie, and who's signed in.
async fn signed_in(client: &deadpool_postgres::Object, user: store::User, credential: &[u8]) -> Result<Response> {
    let token = store::create_session(client, user.id, credential).await?;
    let session = store::Session { user, credential_id: credential.to_vec() };
    let me = me_of(client, &session).await?;
    Ok(([(header::SET_COOKIE, session_cookie(&token))], Json(me)).into_response())
}

#[derive(Deserialize, ToSchema)]
struct Login {
    challenge_id: String,
    credential: Assertion,
}

/// Signs in with a passkey.
#[utoipa::path(post, path = "/login", request_body = Login, responses(
    (status = 200, body = Me, description = "Signed in; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn login(State(console): ConsoleState, Json(body): Json<Login>) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let (challenge, _) = take_challenge(&client, &body.challenge_id, store::Purpose::Login).await?;
    let a = &body.credential;
    let credential_id = unb64(&a.id, "id")?;
    let unknown = || ApiError::BadRequest("this passkey isn't registered with this console (anymore)".into());
    let passkey = store::passkey(&client, &credential_id).await?.ok_or_else(unknown)?;
    if let Some(handle) = &a.user_handle
        && unb64(handle, "user_handle")? != passkey.user.id.as_bytes()
    {
        return Err(unknown());
    }
    let asserted = webauthn::verify_assertion(
        &console.party,
        &challenge,
        &passkey.public_key,
        &unb64(&a.client_data_json, "client_data_json")?,
        &unb64(&a.authenticator_data, "authenticator_data")?,
        &unb64(&a.signature, "signature")?,
    )
    .map_err(refused)?;
    if !store::record_use(&client, &credential_id, asserted.sign_count, asserted.backed_up).await? {
        eprintln!(
            "console: passkey of {:?} signed with counter {} after {}: refused, as it may be a clone",
            passkey.user.name, asserted.sign_count, passkey.sign_count
        );
        return Err(ApiError::BadRequest(
            "this passkey's signature counter went backwards, so it may have been copied; it's refused".into(),
        ));
    }
    signed_in(&client, passkey.user, &credential_id).await
}

/// Signs out: ends the session.
#[utoipa::path(post, path = "/logout", responses(
    (status = 204, description = "Signed out; the cookie is cleared"),
    (status = "5XX", body = ErrorBody),
))]
async fn logout(State(console): ConsoleState, headers: HeaderMap) -> Result<Response> {
    if let Some(token) = session_token(&headers) {
        store::end_session(&console.app.pool.get().await?, &token).await?;
    }
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cleared_cookie())]).into_response())
}

// ─── The signed-in user ──────────────────────────────────────────────────────

/// The signed-in user.
#[derive(Serialize, ToSchema)]
struct Me {
    name: String,
    /// The user's ARN, which policies name it by.
    arn: String,
    admin: bool,
    passkeys: Vec<PasskeySummary>,
}

#[derive(Serialize, ToSchema)]
struct PasskeySummary {
    /// Its credential ID (base64url).
    id: String,
    name: String,
    /// Whether it's synced (backed up) by its provider, as it last said.
    backed_up: bool,
    created_at: f64,
    last_used_at: Option<f64>,
    /// Whether this session was signed in with it.
    current: bool,
}

async fn me_of(client: &deadpool_postgres::Object, session: &store::Session) -> Result<Me> {
    let account = crate::roles::account(client).await?;
    let passkeys = store::passkeys(client, session.user.id).await?;
    Ok(Me {
        name: session.user.name.clone(),
        arn: format!("arn:aws:iam::{account}:user/{}", session.user.name),
        admin: session.user.admin,
        passkeys: passkeys
            .into_iter()
            .map(|p| PasskeySummary {
                current: p.credential_id == session.credential_id,
                id: b64(&p.credential_id),
                name: p.name,
                backed_up: p.backed_up,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            })
            .collect(),
    })
}

#[utoipa::path(get, path = "/me", responses(
    (status = 200, body = Me),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn me(State(console): ConsoleState, signed: Signed) -> Result<Json<Me>> {
    let client = console.app.pool.get().await?;
    Ok(Json(me_of(&client, &signed.session).await?))
}

/// Adds a passkey to the signed-in user.
#[utoipa::path(post, path = "/passkeys", request_body = NewPasskey, responses(
    (status = 204, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_passkey(State(console): ConsoleState, signed: Signed, Json(body): Json<NewPasskey>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    let user = signed.session.user.id;
    let (challenge, owner) = take_challenge(&client, &body.challenge_id, store::Purpose::Add).await?;
    if owner != Some(user) {
        return Err(ApiError::BadRequest("this challenge isn't yours".into()));
    }
    register(&console, &client, user, None, &challenge, &body.name, &body.credential).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PasskeyName {
    name: String,
}

/// Renames one of the signed-in user's passkeys.
#[utoipa::path(put, path = "/passkeys/{id}", params(("id" = String, Path)), request_body = PasskeyName, responses(
    (status = 204, description = "Renamed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn rename_passkey(
    State(console): ConsoleState,
    signed: Signed,
    Path(id): Path<String>,
    Json(body): Json<PasskeyName>,
) -> Result<StatusCode> {
    let name = store::check_name(&body.name)?;
    let client = console.app.pool.get().await?;
    store::rename_passkey(&client, signed.session.user.id, &unb64(&id, "id")?, name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes one of the signed-in user's passkeys (not its last), and ends the
/// sessions signed in with it.
#[utoipa::path(delete, path = "/passkeys/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_passkey(State(console): ConsoleState, signed: Signed, Path(id): Path<String>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    store::delete_passkey(&client, signed.session.user.id, &unb64(&id, "id")?).await?;
    Ok(StatusCode::NO_CONTENT)
}
