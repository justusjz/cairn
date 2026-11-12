//! The console's JSON API, under `/api`: signing in with a passkey (a new
//! login's first through an enrollment link, which adds its identity to a
//! signed-in login instead), switching between the login's accounts,
//! signing out, and the login's own passkeys. Its OpenAPI spec is committed as `ui/console-openapi.json`,
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
        .routes(routes!(enroll_link))
        .routes(routes!(switch))
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
    let mut spec = router().split_for_parts().1;
    spec.merge(crate::dashboard::shared_router().split_for_parts().1);
    spec
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

/// The login a new passkey made with `challenge` is for, when it's a new
/// login's: its ID follows from the challenge, so that the passkey's user
/// handle (which authenticators keep) can be the login's ID before it
/// exists.
fn new_login_id(challenge: &[u8]) -> Uuid {
    let hash = ring::digest::digest(&ring::digest::SHA256, challenge);
    Uuid::from_slice(&hash.as_ref()[..16]).expect("16 bytes")
}

/// Options to register a passkey for `login` (its ID, the user handle),
/// named `name`, not on an authenticator that has one of `existing` already.
fn creation_options(console: &Console, login: Uuid, name: &str, challenge: &[u8], existing: &[Vec<u8>]) -> Value {
    json!({
        "rp": { "id": console.party.id, "name": "Cairn" },
        "user": { "id": b64(login.as_bytes()), "name": name, "displayName": name },
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

/// Options to sign with a passkey: any the authenticator has for the
/// console, which says whose it is.
fn request_options(console: &Console, challenge: &[u8]) -> Value {
    json!({
        "challenge": b64(challenge),
        "rpId": console.party.id,
        "timeout": store::CHALLENGE_TTL.as_millis() as u64,
        "userVerification": "required",
        "allowCredentials": [],
    })
}

#[derive(Deserialize, ToSchema)]
struct Enrollment {
    /// The token of the enrollment link (after its `#`).
    token: String,
}

/// What an enrollment link is for, and the options to make a new login's
/// passkey for it (signed out; signed in, `/enroll/link` adds it to the
/// login instead).
#[derive(Serialize, ToSchema)]
struct EnrollCeremony {
    /// The identity: `user @ account`, or `root @ account`.
    identity: String,
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
    let Some(identity) = store::enrollment(&client, &body.token).await? else {
        return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into()));
    };
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Enroll, None).await?;
    let label = identity.label();
    let options = creation_options(&console, new_login_id(&challenge), &label, &challenge, &[]);
    Ok(Json(EnrollCeremony { identity: label, ceremony: Ceremony { challenge_id: id.to_string(), options } }))
}

#[utoipa::path(post, path = "/login/options", responses(
    (status = 200, body = Ceremony),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn login_options(State(console): ConsoleState) -> Result<Json<Ceremony>> {
    let client = console.app.pool.get().await?;
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Login, None).await?;
    Ok(Json(Ceremony { challenge_id: id.to_string(), options: request_options(&console, &challenge) }))
}

#[utoipa::path(post, path = "/passkeys/options", responses(
    (status = 200, body = Ceremony),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn passkey_options(State(console): ConsoleState, signed: Signed) -> Result<Json<Ceremony>> {
    let client = console.app.pool.get().await?;
    let session = signed.session;
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Add, Some(session.login)).await?;
    let existing = store::credential_ids(&client, session.login).await?;
    let options = creation_options(&console, session.login, &session.login_name, &challenge, &existing);
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
    /// The login the passkey is of, as the authenticator says.
    user_handle: Option<String>,
}

/// Takes challenge `id` for `purpose`: its bytes, and whose it is.
async fn take_challenge(
    client: &deadpool_postgres::Object,
    id: &str,
    purpose: store::Purpose,
) -> Result<(Vec<u8>, Option<Uuid>)> {
    let expired = || ApiError::BadRequest("this took too long, or was done already; try again".into());
    let id: Uuid = id.parse().map_err(|_| expired())?;
    store::take_challenge(client, id, purpose).await?.ok_or_else(expired)
}

/// Checks a registration against its challenge: the passkey it made, named
/// `name`.
fn registered(console: &Console, challenge: &[u8], registration: &Registration) -> Result<webauthn::NewCredential> {
    let client_data = unb64(&registration.client_data_json, "client_data_json")?;
    let attestation = unb64(&registration.attestation_object, "attestation_object")?;
    let credential = webauthn::verify_registration(&console.party, challenge, &client_data, &attestation).map_err(refused)?;
    if unb64(&registration.id, "id")? != credential.id {
        return Err(ApiError::BadRequest("the credential's ID isn't the one it was registered with".into()));
    }
    Ok(credential)
}

fn new_passkey<'a>(credential: &'a webauthn::NewCredential, name: &'a str) -> store::NewPasskey<'a> {
    store::NewPasskey {
        credential_id: &credential.id,
        public_key: &credential.public_key,
        sign_count: credential.sign_count,
        name,
        backup_eligible: credential.backup_eligible,
        backed_up: credential.backed_up,
    }
}

/// Checks an assertion against its challenge: the login whose passkey made
/// it, whose use is recorded.
async fn asserted(console: &Console, client: &deadpool_postgres::Object, challenge: &[u8], a: &Assertion) -> Result<(Uuid, Vec<u8>)> {
    let credential_id = unb64(&a.id, "id")?;
    let unknown = || ApiError::BadRequest("this passkey isn't registered with this console (anymore)".into());
    let passkey = store::passkey(client, &credential_id).await?.ok_or_else(unknown)?;
    if let Some(handle) = &a.user_handle
        && unb64(handle, "user_handle")? != passkey.login.as_bytes()
    {
        return Err(unknown());
    }
    let asserted = webauthn::verify_assertion(
        &console.party,
        challenge,
        &passkey.public_key,
        &unb64(&a.client_data_json, "client_data_json")?,
        &unb64(&a.authenticator_data, "authenticator_data")?,
        &unb64(&a.signature, "signature")?,
    )
    .map_err(refused)?;
    if !store::record_use(client, &credential_id, asserted.sign_count, asserted.backed_up).await? {
        eprintln!(
            "console: a passkey of login {} signed with counter {} after {}: refused, as it may be a clone",
            passkey.login, asserted.sign_count, passkey.sign_count
        );
        return Err(ApiError::BadRequest(
            "this passkey's signature counter went backwards, so it may have been copied; it's refused".into(),
        ));
    }
    Ok((passkey.login, credential_id))
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

/// Makes a new login, with a first passkey, for an enrollment link's
/// identity (using the link up), and signs in with it.
#[utoipa::path(post, path = "/enroll", request_body = Enroll, responses(
    (status = 200, body = Me, description = "Signed in; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enroll(State(console): ConsoleState, Json(body): Json<Enroll>) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let p = &body.passkey;
    let name = store::check_name(&p.name)?;
    let (challenge, _) = take_challenge(&client, &p.challenge_id, store::Purpose::Enroll).await?;
    let Some(identity) = store::enrollment(&client, &body.token).await? else {
        return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into()));
    };
    let credential = registered(&console, &challenge, &p.credential)?;
    let login = new_login_id(&challenge);
    let account = store::new_login(&client, login, &identity.label(), &body.token, &new_passkey(&credential, name)).await?;
    signed_in(&client, login, &account, &credential.id).await
}

/// Starts a session for `login`, signed in with `credential` (just now), as
/// its identity in `account`: the response with its cookie, and who's
/// signed in.
async fn signed_in(client: &deadpool_postgres::Object, login: Uuid, account: &str, credential: &[u8]) -> Result<Response> {
    let token = store::create_session(client, login, account, credential).await?;
    let session = store::session(client, &token).await?.ok_or_else(|| anyhow::anyhow!("a new session is gone"))?;
    let me = me_of(client, &session).await?;
    Ok(([(header::SET_COOKIE, session_cookie(&token))], Json(me)).into_response())
}

#[derive(Deserialize, ToSchema)]
struct Login {
    challenge_id: String,
    credential: Assertion,
}

/// Signs in with a passkey, as the login's identity in its first account
/// (by name; the operator account last).
#[utoipa::path(post, path = "/login", request_body = Login, responses(
    (status = 200, body = Me, description = "Signed in; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn login(State(console): ConsoleState, Json(body): Json<Login>) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let (challenge, _) = take_challenge(&client, &body.challenge_id, store::Purpose::Login).await?;
    let (login, credential) = asserted(&console, &client, &challenge, &body.credential).await?;
    let identities = store::identities(&client, login).await?;
    let Some(first) = identities.first() else {
        return Err(ApiError::Forbidden(
            "this login isn't in any account (anymore): ask an administrator for an enrollment link".into(),
        ));
    };
    signed_in(&client, login, &first.account_id, &credential).await
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

/// Adds an enrollment link's identity to the signed-in login (using the
/// link up), and acts as it, unless it's the operator account's, which
/// takes a fresh passkey assertion first (`/switch`).
#[utoipa::path(post, path = "/enroll/link", request_body = Enrollment, responses(
    (status = 200, body = Me),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enroll_link(State(console): ConsoleState, signed: Signed, Json(body): Json<Enrollment>) -> Result<Json<Me>> {
    let client = console.app.pool.get().await?;
    let account = store::enroll(&client, signed.session.login, &body.token).await?;
    let identities = store::identities(&client, signed.session.login).await?;
    let operator = identities.iter().any(|i| i.account_id == account && i.operator);
    if !operator || signed.session.fresh {
        store::switch(&client, &signed.token, &account, false).await?;
    }
    let session = store::session(&client, &signed.token).await?.ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
    Ok(Json(me_of(&client, &session).await?))
}

#[derive(Deserialize, ToSchema)]
struct Switch {
    /// The account (its ID) to act in.
    account_id: String,
    /// A fresh assertion, for the operator account, if the session's
    /// passkey wasn't used within five minutes (`Me.fresh`): its challenge
    /// (from `/login/options`) and the browser's response.
    challenge_id: Option<String>,
    credential: Option<Assertion>,
}

/// Acts as the login's identity in another account.
#[utoipa::path(post, path = "/switch", request_body = Switch, responses(
    (status = 200, body = Me),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn switch(State(console): ConsoleState, signed: Signed, Json(body): Json<Switch>) -> Result<Json<Me>> {
    let client = console.app.pool.get().await?;
    let identities = store::identities(&client, signed.session.login).await?;
    let Some(target) = identities.iter().find(|i| i.account_id == body.account_id) else {
        return Err(ApiError::NotFound("you're not in that account".into()));
    };
    let verified = match (&body.challenge_id, &body.credential) {
        (Some(id), Some(credential)) => {
            let (challenge, _) = take_challenge(&client, id, store::Purpose::Login).await?;
            let (login, _) = asserted(&console, &client, &challenge, credential).await?;
            if login != signed.session.login {
                return Err(ApiError::BadRequest("that passkey is another login's".into()));
            }
            true
        }
        _ => false,
    };
    if target.operator && !verified && !signed.session.fresh {
        return Err(ApiError::Unauthorized("confirm with your passkey to act as the operator".into()));
    }
    store::switch(&client, &signed.token, &body.account_id, verified).await?;
    let session = store::session(&client, &signed.token).await?.ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
    Ok(Json(me_of(&client, &session).await?))
}

// ─── The signed-in login ─────────────────────────────────────────────────────

/// An identity of the login.
#[derive(Serialize, ToSchema)]
struct IdentitySummary {
    account_id: String,
    account: String,
    /// Whether it's the operator account's (the superadmins').
    operator: bool,
    /// The user's name; `null`: the account's root.
    user: Option<String>,
    /// The identity's ARN, which policies name it by.
    arn: String,
    /// Whether the user has `AdministratorAccess` (a root may do anything in
    /// its account anyway).
    admin: bool,
}

impl IdentitySummary {
    fn of(identity: &store::Identity) -> IdentitySummary {
        IdentitySummary {
            account_id: identity.account_id.clone(),
            account: identity.account.clone(),
            operator: identity.operator,
            user: identity.user.as_ref().map(|u| u.name.clone()),
            arn: identity.arn(),
            admin: identity.user.as_ref().is_some_and(|u| u.admin),
        }
    }
}

/// The signed-in login: who it acts as now, its identities, its passkeys.
#[derive(Serialize, ToSchema)]
struct Me {
    /// The login's name.
    name: String,
    /// Who the session acts as.
    identity: IdentitySummary,
    /// Every identity of the login, the operator account's last.
    identities: Vec<IdentitySummary>,
    /// Whether its passkey was used within five minutes: acting as the
    /// operator takes that.
    fresh: bool,
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
    let identities = store::identities(client, session.login).await?;
    let passkeys = store::passkeys(client, session.login).await?;
    Ok(Me {
        name: session.login_name.clone(),
        identity: IdentitySummary::of(&session.identity),
        identities: identities.iter().map(IdentitySummary::of).collect(),
        fresh: session.fresh,
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

/// Adds a passkey to the signed-in login.
#[utoipa::path(post, path = "/passkeys", request_body = NewPasskey, responses(
    (status = 204, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_passkey(State(console): ConsoleState, signed: Signed, Json(body): Json<NewPasskey>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    let login = signed.session.login;
    let name = store::check_name(&body.name)?;
    let (challenge, owner) = take_challenge(&client, &body.challenge_id, store::Purpose::Add).await?;
    if owner != Some(login) {
        return Err(ApiError::BadRequest("this challenge isn't yours".into()));
    }
    let credential = registered(&console, &challenge, &body.credential)?;
    store::add_passkey(&client, login, &new_passkey(&credential, name)).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PasskeyName {
    name: String,
}

/// Renames one of the signed-in login's passkeys.
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
    store::rename_passkey(&client, signed.session.login, &unb64(&id, "id")?, name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removes one of the signed-in login's passkeys (not its last), and ends
/// the sessions signed in with it.
#[utoipa::path(delete, path = "/passkeys/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_passkey(State(console): ConsoleState, signed: Signed, Path(id): Path<String>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    store::delete_passkey(&client, signed.session.login, &unb64(&id, "id")?).await?;
    Ok(StatusCode::NO_CONTENT)
}
