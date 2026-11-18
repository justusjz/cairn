//! The console's JSON API, under `/api`: signing in with a passkey (a new
//! login's first through an enrollment link, which adds its identity to a
//! signed-in login instead), or at an identity source as a directory user
//! (who picks a permission set, and may take its credentials), signing out,
//! and the login's own passkeys. Its OpenAPI spec, with
//! `manage`'s routes, is committed as `ui/openapi.json`, which the UI's
//! types are generated from.
//!
//! The ceremonies take two requests each: the options (with a challenge,
//! kept in the database for five minutes, and used once), which the page
//! hands `navigator.credentials`, and the browser's response, which the
//! server checks (`webauthn`). Binary values travel as unpadded base64url,
//! as in WebAuthn's own JSON forms.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{Console, DirectorySigned, PasskeyHolder, Signed, cleared_cookie, root_cookie, session_cookie, session_token, store, webauthn};
use super::web::{ApiError, ErrorBody};

type Result<T> = std::result::Result<T, ApiError>;
type ConsoleState = State<Arc<Console>>;

#[derive(OpenApi)]
#[openapi(
    info(title = "Cairn console", description = "The API of Cairn's console."),
    servers((url = "/api")),
    components(schemas(ErrorBody))
)]
struct Doc;

pub(super) fn router() -> OpenApiRouter<Arc<Console>> {
    OpenApiRouter::with_openapi(Doc::openapi())
        .routes(routes!(enroll_options))
        .routes(routes!(enroll))
        .routes(routes!(enroll_link))
        .routes(routes!(login_options))
        .routes(routes!(login))
        .routes(routes!(logout))
        .routes(routes!(root_sign_in))
        .routes(routes!(me))
        .routes(routes!(passkey_options))
        .routes(routes!(add_passkey))
        .routes(routes!(rename_passkey, delete_passkey))
        .routes(routes!(oidc_providers))
        .routes(routes!(setup))
        .routes(routes!(oidc_start))
        .routes(routes!(oidc_callback))
        .routes(routes!(choose_permission_set))
        .routes(routes!(directory_credentials))
}

/// The API's OpenAPI spec, as committed in `ui/openapi.json`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut spec = router().split_for_parts().1;
    spec.merge(super::manage::router().split_for_parts().1);
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
    /// The identity: `user @ account`, or a directory user's user name.
    identity: String,
    /// Whether the link is a directory user's setup link (whose passkey is
    /// its own, never a login's).
    directory: bool,
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
    let (handle, label, directory) = match store::enrollment(&client, &body.token).await? {
        Some(identity) => (None, identity.label(), false),
        // A directory user's setup link: its passkeys' user handle is its ID.
        None => match store::setup_link(&client, &body.token).await? {
            Some((user, name)) => (Some(user), name, true),
            None => return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into())),
        },
    };
    let (id, challenge) = store::create_challenge(&client, store::Purpose::Enroll, None).await?;
    let options = creation_options(&console, handle.unwrap_or_else(|| new_login_id(&challenge)), &label, &challenge, &[]);
    Ok(Json(EnrollCeremony { identity: label, directory, ceremony: Ceremony { challenge_id: id.to_string(), options } }))
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
async fn passkey_options(State(console): ConsoleState, holder: PasskeyHolder) -> Result<Json<Ceremony>> {
    let client = console.app.pool.get().await?;
    let options = match holder {
        PasskeyHolder::Login(session) => {
            let (id, challenge) = store::create_challenge(&client, store::Purpose::Add, Some(session.login)).await?;
            let existing = store::credential_ids(&client, session.login).await?;
            (id, creation_options(&console, session.login, &session.login_name, &challenge, &existing))
        }
        // Its passkeys' user handle is its ID, as its setup link's.
        PasskeyHolder::Directory(session) => {
            let (id, challenge) = store::create_directory_challenge(&client, session.user_id).await?;
            let existing = store::directory_credential_ids(&client, session.user_id).await?;
            (id, creation_options(&console, session.user_id, &session.user_name, &challenge, &existing))
        }
    };
    Ok(Json(Ceremony { challenge_id: options.0.to_string(), options: options.1 }))
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

/// Takes challenge `id` for `purpose`.
async fn take_challenge(client: &deadpool_postgres::Object, id: &str, purpose: store::Purpose) -> Result<store::Challenge> {
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

/// Who signed with a passkey: a login, or a user of Cairn's own directory
/// (its ID), and the passkey's credential ID.
enum Signer {
    Login(Uuid, Vec<u8>),
    Directory(Uuid, Vec<u8>),
}

/// Checks an assertion against its challenge, with a directory user's
/// passkey: who signed, whose use is recorded.
async fn asserted_directory(
    console: &Console,
    client: &deadpool_postgres::Object,
    challenge: &[u8],
    a: &Assertion,
    credential_id: Vec<u8>,
    passkey: store::DirectoryPasskey,
) -> Result<Signer> {
    let unknown = || ApiError::BadRequest("this passkey isn't registered with this console (anymore)".into());
    if let Some(handle) = &a.user_handle
        && unb64(handle, "user_handle")? != passkey.user.as_bytes()
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
    if !store::record_directory_use(client, &credential_id, asserted.sign_count, asserted.backed_up).await? {
        eprintln!(
            "console: a passkey of directory user {} signed with counter {} after {}: refused, as it may be a clone",
            passkey.user, asserted.sign_count, passkey.sign_count
        );
        return Err(ApiError::BadRequest(
            "this passkey's signature counter went backwards, so it may have been copied; it's refused".into(),
        ));
    }
    Ok(Signer::Directory(passkey.user, credential_id))
}

/// Checks an assertion against its challenge: who signed (a login, or a
/// user of Cairn's own directory), whose passkey's use is recorded.
async fn asserted(console: &Console, client: &deadpool_postgres::Object, challenge: &[u8], a: &Assertion) -> Result<Signer> {
    let credential_id = unb64(&a.id, "id")?;
    let unknown = || ApiError::BadRequest("this passkey isn't registered with this console (anymore)".into());
    let passkey = match store::passkey(client, &credential_id).await? {
        Some(passkey) => passkey,
        None => match store::directory_passkey(client, &credential_id).await? {
            Some(passkey) => return asserted_directory(console, client, challenge, a, credential_id, passkey).await,
            None => return Err(unknown()),
        },
    };
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
    Ok(Signer::Login(passkey.login, credential_id))
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
    let challenge = take_challenge(&client, &p.challenge_id, store::Purpose::Enroll).await?.bytes;
    let Some(identity) = store::enrollment(&client, &body.token).await? else {
        // A directory user's setup link: its first (or another) passkey,
        // and it's signed in with it.
        if store::setup_link(&client, &body.token).await?.is_some() {
            let credential = registered(&console, &challenge, &p.credential)?;
            let user = store::new_directory_passkey(&client, &body.token, &new_passkey(&credential, name)).await?;
            return directory_signed_in(&console, &client, user, &credential.id).await;
        }
        return Err(ApiError::BadRequest("this enrollment link has been used, or has expired".into()));
    };
    let credential = registered(&console, &challenge, &p.credential)?;
    let login = new_login_id(&challenge);
    let account = store::new_login(&client, login, &identity.label(), &body.token, &new_passkey(&credential, name)).await?;
    signed_in(&console, &client, login, &account, &credential.id).await
}

/// Starts a session for `login`, signed in with passkey `credential` (just
/// now), as its identity in `account`: the response with its cookie, and
/// who's signed in.
async fn signed_in(
    console: &Console,
    client: &deadpool_postgres::Object,
    login: Uuid,
    account: &str,
    credential: &[u8],
) -> Result<Response> {
    let token = store::create_session(client, login, account, credential).await?;
    let session = store::session(client, &token).await?.ok_or_else(|| anyhow::anyhow!("a new session is gone"))?;
    let me = me_of(console, client, &session).await?;
    Ok(([(header::SET_COOKIE, session_cookie(&token))], Json(me)).into_response())
}

/// Starts a session for directory user `user` of Cairn's own directory,
/// signed in with passkey `credential` (just now), as Identity Center's
/// access portal would let it in: with one of the permission sets assigned
/// to it (picked for it if it has one), none, if it has none.
async fn directory_signed_in(console: &Console, client: &deadpool_postgres::Object, user: Uuid, credential: &[u8]) -> Result<Response> {
    let account = crate::users::account(client).await?;
    let eligible = crate::identity_center::eligible(client, &account, user).await?;
    if eligible.is_empty() {
        return Err(ApiError::Forbidden(
            "your passkey works, but no permission set is assigned to you: ask an administrator for one".into(),
        ));
    }
    let chosen = match eligible.as_slice() {
        [only] => Some((only.set.id, only.account.as_str())),
        _ => None,
    };
    let token = store::create_directory_session(client, &account, user, chosen, Some(credential)).await?;
    let session = store::directory_session(client, &token).await?.ok_or_else(|| anyhow::anyhow!("a new session is gone"))?;
    let me = directory_me(console, client, &session).await?;
    Ok(([(header::SET_COOKIE, session_cookie(&token))], Json(me)).into_response())
}

#[derive(Deserialize, ToSchema)]
struct Login {
    challenge_id: String,
    credential: Assertion,
}

/// Signs in with a passkey, as the login's identity.
#[utoipa::path(post, path = "/login", request_body = Login, responses(
    (status = 200, body = Me, description = "Signed in; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn login(State(console): ConsoleState, Json(body): Json<Login>) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let challenge = take_challenge(&client, &body.challenge_id, store::Purpose::Login).await?.bytes;
    let (login, credential) = match asserted(&console, &client, &challenge, &body.credential).await? {
        Signer::Login(login, credential) => (login, credential),
        Signer::Directory(user, credential) => return directory_signed_in(&console, &client, user, &credential).await,
    };
    let identities = store::identities(&client, login).await?;
    let Some(first) = identities.first() else {
        return Err(ApiError::Forbidden(
            "this login isn't in any account (anymore): ask an administrator for an enrollment link".into(),
        ));
    };
    signed_in(&console, &client, login, &first.account_id, &credential).await
}

#[derive(Deserialize, ToSchema)]
struct RootSignIn {
    /// The token of the root user's link (after its `#`).
    token: String,
}

/// Signs in as the account's root user, with a link the command line on a
/// node made (`cairn account root-link`), which it uses up. The session is
/// short (an hour at most), and not multi-factor.
#[utoipa::path(post, path = "/root/sign-in", request_body = RootSignIn, responses(
    (status = 200, body = Me, description = "Signed in as the root user; the session's cookie is set"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn root_sign_in(
    State(console): ConsoleState,
    headers: HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<RootSignIn>,
) -> Result<Response> {
    let client = console.app.pool.get().await?;
    let Some(token) = store::root_sign_in(&client, &body.token).await? else {
        return Err(ApiError::BadRequest(
            "this link has been used, or has expired: make another on a node (`cairn account root-link`)".into(),
        ));
    };
    // It replaces the browser's session, if it had one.
    if let Some(old) = session_token(&headers) {
        store::end_session(&client, &old).await?;
    }
    let root = store::root_session(&client, &token).await?.ok_or_else(|| anyhow::anyhow!("a new session is gone"))?;
    // Who was the root, and from where, is for the node's log.
    let peer = peer.map(|p| p.0.0.ip());
    let from = crate::s3::access::client_address(&headers, peer, &console.app.trusted_proxies);
    let from = from.map(|ip| format!(" from {ip}")).unwrap_or_default();
    eprintln!("console: signed in as the root user of account {}{from}", root.account_id);
    let me = root_me(&console, &root).await?;
    Ok(([(header::SET_COOKIE, root_cookie(&token))], Json(me)).into_response())
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
/// link up).
#[utoipa::path(post, path = "/enroll/link", request_body = Enrollment, responses(
    (status = 200, body = Me),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn enroll_link(State(console): ConsoleState, signed: Signed, Json(body): Json<Enrollment>) -> Result<Json<Me>> {
    let client = console.app.pool.get().await?;
    if store::setup_link(&client, &body.token).await?.is_some() {
        return Err(ApiError::BadRequest("this is a directory user's link: make a passkey of its own with it".into()));
    }
    store::enroll(&client, signed.session.login, &body.token).await?;
    let session = store::session(&client, &signed.token).await?.ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
    Ok(Json(me_of(&console, &client, &session).await?))
}

// ─── The signed-in login ─────────────────────────────────────────────────────

/// Who the login is: a user of the account.
#[derive(Serialize, ToSchema)]
struct IdentitySummary {
    account_id: String,
    account: String,
    /// The user's name.
    user: String,
    /// The user's ARN, which policies name it by.
    arn: String,
    /// Whether its account is the organization's management account, whose
    /// alone Identity Center and the organization are.
    management: bool,
}

impl IdentitySummary {
    fn of(identity: &store::Identity, management: &str) -> IdentitySummary {
        IdentitySummary {
            account_id: identity.account_id.clone(),
            account: identity.account.clone(),
            user: identity.user.name.clone(),
            arn: identity.arn(),
            management: identity.account_id == management,
        }
    }
}

/// The signed-in login: who it acts as, its passkeys. Or the account's
/// root user (`root`), or a directory user (`directory`), which have no
/// login: no passkeys.
#[derive(Serialize, ToSchema)]
struct Me {
    /// The login's name (`root` for the root user; a directory user's own).
    name: String,
    /// Whether the session is the account's root user's, which no identity
    /// policy restricts (only resource policies' denies do).
    root: bool,
    /// When the root user's session ends at the latest (seconds since the
    /// epoch); a login's has none here.
    expires_at: Option<f64>,
    /// Who the session acts as.
    identity: IdentitySummary,
    /// Whether it was signed in with a passkey (`aws:MultiFactorAuthPresent`).
    mfa: bool,
    /// Whether it may see the cluster (`cairn:GetCluster`): it's an
    /// operator, and the console shows it the cluster's pages.
    cluster: bool,
    passkeys: Vec<PasskeySummary>,
    /// A directory user's session: who it is at its identity source, and
    /// its permission sets.
    directory: Option<DirectoryMe>,
}

/// A directory user, signed in at an identity source.
#[derive(Serialize, ToSchema)]
struct DirectoryMe {
    /// Its ID in the identity store, and its user name there.
    user_id: String,
    user_name: String,
    /// The identity source's name and label, and its subject there (`sub`);
    /// none for a user of Cairn's own directory, which signs in with
    /// passkeys.
    provider: Option<String>,
    provider_label: Option<String>,
    subject: Option<String>,
    email: Option<String>,
    /// Its groups, as the source's group claim said when it signed in.
    groups: Vec<String>,
    /// The permission set it acts as, and the account (by ID) it acts in
    /// there, if it picked one.
    permission_set: Option<String>,
    permission_set_account_id: Option<String>,
    /// The permission sets assigned to it or its groups, in the accounts
    /// they're assigned in, to pick from.
    permission_sets: Vec<PermissionSetChoice>,
}

/// A permission set a directory user may use, in an account.
#[derive(Serialize, ToSchema)]
struct PermissionSetChoice {
    /// The account's ID and name.
    account_id: String,
    account: String,
    name: String,
    description: String,
    /// How long its sessions (and credentials) last, in seconds.
    session_duration: i32,
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

async fn me_of(console: &Console, client: &deadpool_postgres::Object, session: &store::Session) -> Result<Me> {
    // As a page of the console would ask it.
    let user = super::session_user(client, session, axum::http::Method::GET, HeaderMap::new(), String::new(), None).await?;
    let cluster = match user {
        Some(user) => {
            let actor = super::Actor(Arc::new(user));
            actor.allows(&console.app, "cairn:GetCluster", crate::s3::actions::On::Cluster).await?
        }
        None => false,
    };
    let passkeys = store::passkeys(client, session.login).await?;
    Ok(Me {
        directory: None,
        name: session.login_name.clone(),
        root: false,
        expires_at: None,
        identity: IdentitySummary::of(&session.identity, &crate::users::account(client).await?),
        mfa: true,
        cluster,
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
async fn me(State(console): ConsoleState, headers: HeaderMap) -> Result<Json<Me>> {
    let unauthorized = || ApiError::Unauthorized("sign in first".into());
    let token = session_token(&headers).ok_or_else(unauthorized)?;
    let client = console.app.pool.get().await?;
    if let Some(session) = store::session(&client, &token).await? {
        return Ok(Json(me_of(&console, &client, &session).await?));
    }
    if let Some(session) = store::directory_session(&client, &token).await? {
        return Ok(Json(directory_me(&console, &client, &session).await?));
    }
    let root = store::root_session(&client, &token).await?.ok_or_else(unauthorized)?;
    Ok(Json(root_me(&console, &root).await?))
}

/// Who a directory user's session is: as its permission set's role's
/// session, if it picked one that's still its.
async fn directory_me(console: &Console, client: &deadpool_postgres::Object, session: &store::DirectorySession) -> Result<Me> {
    let eligible = crate::identity_center::eligible(client, &session.account_id, session.user_id).await?;
    let management = crate::users::account(client).await?;
    let chosen = eligible.iter().find(|e| session.permission_set.as_ref() == Some(&(e.set.id, e.account.clone())));
    let (identity, cluster) = match chosen {
        Some(chosen) => {
            let user = super::directory::user(client, session, axum::http::Method::GET, HeaderMap::new(), String::new(), None).await?;
            let arn = user.principal.arn();
            let actor = super::Actor(Arc::new(user));
            let cluster = actor.allows(&console.app, "cairn:GetCluster", crate::s3::actions::On::Cluster).await?;
            let identity = IdentitySummary {
                account_id: chosen.account.clone(),
                account: chosen.account_name.clone(),
                user: chosen.role_name.clone(),
                arn,
                management: chosen.account == management,
            };
            (identity, cluster)
        }
        None => {
            let identity = IdentitySummary {
                account_id: session.account_id.clone(),
                account: session.account.clone(),
                user: String::new(),
                arn: String::new(),
                management: session.account_id == management,
            };
            (identity, false)
        }
    };
    Ok(Me {
        name: session.name.clone(),
        root: false,
        expires_at: Some(session.expires_at),
        identity,
        mfa: session.mfa_age.is_some(),
        cluster,
        passkeys: match session.provider {
            Some(_) => Vec::new(),
            None => store::directory_passkeys(client, session.user_id)
                .await?
                .into_iter()
                .map(|p| PasskeySummary {
                    current: session.credential_id.as_ref() == Some(&p.credential_id),
                    id: b64(&p.credential_id),
                    name: p.name,
                    backed_up: p.backed_up,
                    created_at: p.created_at,
                    last_used_at: p.last_used_at,
                })
                .collect(),
        },
        directory: Some(DirectoryMe {
            user_id: session.user_id.to_string(),
            user_name: session.user_name.clone(),
            provider: session.provider.clone(),
            provider_label: session.provider_label.clone(),
            subject: session.subject.clone(),
            email: session.email.clone(),
            groups: session.groups.clone(),
            permission_set: chosen.map(|e| e.set.name.clone()),
            permission_set_account_id: chosen.map(|e| e.account.clone()),
            permission_sets: eligible
                .iter()
                .map(|e| PermissionSetChoice {
                    account_id: e.account.clone(),
                    account: e.account_name.clone(),
                    name: e.set.name.clone(),
                    description: e.set.description.clone(),
                    session_duration: e.set.session_duration,
                })
                .collect(),
        }),
    })
}

#[derive(Deserialize, ToSchema)]
struct ChosenPermissionSet {
    /// One of the session's permission sets, by name.
    name: String,
    /// The account to act in, by ID: one the set is assigned to the user
    /// in. Needed only when it's assigned in more than one.
    account_id: Option<String>,
}

/// Has a directory user's session act as one of its permission sets.
#[utoipa::path(post, path = "/directory/permission-set", request_body = ChosenPermissionSet, responses(
    (status = 200, body = Me),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn choose_permission_set(
    State(console): ConsoleState,
    signed: DirectorySigned,
    Json(body): Json<ChosenPermissionSet>,
) -> Result<Json<Me>> {
    let client = console.app.pool.get().await?;
    let session = &signed.session;
    let eligible = crate::identity_center::eligible(&client, &session.account_id, session.user_id).await?;
    let matching: Vec<_> = eligible
        .into_iter()
        .filter(|e| e.set.name == body.name && body.account_id.as_ref().is_none_or(|id| *id == e.account))
        .collect();
    let chosen = match matching.as_slice() {
        [] => match &body.account_id {
            Some(id) => return Err(ApiError::Forbidden(format!("the permission set {:?} isn't assigned to you in account {id}", body.name))),
            None => return Err(ApiError::Forbidden(format!("the permission set {:?} isn't assigned to you", body.name))),
        },
        [one] => one,
        _ => return Err(ApiError::BadRequest(format!("the permission set {:?} is yours in several accounts: say which", body.name))),
    };
    store::choose_permission_set(&client, &signed.token, chosen.set.id, &chosen.account).await?;
    let session = store::directory_session(&client, &signed.token).await?.ok_or_else(|| ApiError::Unauthorized("sign in first".into()))?;
    Ok(Json(directory_me(&console, &client, &session).await?))
}

/// Temporary credentials of a session's role, for the CLI and SDKs.
#[derive(Serialize, ToSchema)]
struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    /// When they expire (seconds since the epoch).
    expiration: u64,
}

/// Hands a directory user credentials of its permission set's role, for its
/// session duration, as Identity Center's access portal does. They work
/// until they expire, whatever becomes of the console's session.
#[utoipa::path(post, path = "/directory/credentials", responses(
    (status = 200, body = Credentials),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn directory_credentials(State(console): ConsoleState, signed: DirectorySigned) -> Result<Json<Credentials>> {
    let client = console.app.pool.get().await?;
    let chosen = super::directory::permission_set(&client, &signed.session).await?;
    let mut session = super::directory::role_session(&chosen, &signed.session)?;
    let token = console.app.sessions.seal(&client, &mut session).await?;
    eprintln!(
        "console: credentials {} of permission set {} in account {} for directory user {} ({} of {})",
        session.key_id,
        chosen.set.name,
        chosen.account,
        signed.session.user_name,
        signed.session.subject.as_deref().unwrap_or("-"),
        signed.session.provider.as_deref().unwrap_or("Cairn's own directory")
    );
    Ok(Json(Credentials {
        access_key_id: session.key_id,
        secret_access_key: session.secret,
        session_token: token,
        expiration: session.expires,
    }))
}

/// Who the account's root user's session `root` is.
async fn root_me(console: &Console, root: &store::RootSession) -> Result<Me> {
    let user = super::root_user(root, axum::http::Method::GET, HeaderMap::new(), String::new(), None);
    let actor = super::Actor(Arc::new(user));
    let cluster = actor.allows(&console.app, "cairn:GetCluster", crate::s3::actions::On::Cluster).await?;
    let management = crate::users::account(&console.app.pool.get().await?).await?;
    Ok(Me {
        name: "root".into(),
        root: true,
        expires_at: Some(root.expires_at),
        identity: IdentitySummary {
            account_id: root.account_id.clone(),
            account: root.account.clone(),
            user: "root".into(),
            arn: actor.principal().arn(),
            management: root.account_id == management,
        },
        mfa: false,
        cluster,
        passkeys: Vec::new(),
        directory: None,
    })
}

/// Adds a passkey to the signed-in login, or user of Cairn's own directory.
#[utoipa::path(post, path = "/passkeys", request_body = NewPasskey, responses(
    (status = 204, description = "Added"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn add_passkey(State(console): ConsoleState, holder: PasskeyHolder, Json(body): Json<NewPasskey>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    let name = store::check_name(&body.name)?;
    let challenge = take_challenge(&client, &body.challenge_id, store::Purpose::Add).await?;
    let (login, user) = match &holder {
        PasskeyHolder::Login(session) => (Some(session.login), None),
        PasskeyHolder::Directory(session) => (None, Some(session.user_id)),
    };
    if (challenge.login, challenge.directory_user) != (login, user) {
        return Err(ApiError::BadRequest("this challenge isn't yours".into()));
    }
    let credential = registered(&console, &challenge.bytes, &body.credential)?;
    let key = new_passkey(&credential, name);
    match holder {
        PasskeyHolder::Login(session) => store::add_passkey(&client, session.login, &key).await?,
        PasskeyHolder::Directory(session) => store::add_directory_passkey(&client, session.user_id, &key).await?,
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, ToSchema)]
struct PasskeyName {
    name: String,
}

/// Renames one of the signed-in login's (or own directory user's) passkeys.
#[utoipa::path(put, path = "/passkeys/{id}", params(("id" = String, Path)), request_body = PasskeyName, responses(
    (status = 204, description = "Renamed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn rename_passkey(
    State(console): ConsoleState,
    holder: PasskeyHolder,
    Path(id): Path<String>,
    Json(body): Json<PasskeyName>,
) -> Result<StatusCode> {
    let name = store::check_name(&body.name)?;
    let client = console.app.pool.get().await?;
    let id = unb64(&id, "id")?;
    match holder {
        PasskeyHolder::Login(session) => store::rename_passkey(&client, session.login, &id, name).await?,
        PasskeyHolder::Directory(session) => store::rename_directory_passkey(&client, session.user_id, &id, name).await?,
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Removes one of the signed-in login's (or own directory user's) passkeys
/// (not its last), and ends the sessions signed in with it.
#[utoipa::path(delete, path = "/passkeys/{id}", params(("id" = String, Path)), responses(
    (status = 204, description = "Removed"),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn delete_passkey(State(console): ConsoleState, holder: PasskeyHolder, Path(id): Path<String>) -> Result<StatusCode> {
    let client = console.app.pool.get().await?;
    let id = unb64(&id, "id")?;
    match holder {
        PasskeyHolder::Login(session) => store::delete_passkey(&client, session.login, &id).await?,
        PasskeyHolder::Directory(session) => store::delete_directory_passkey(&client, session.user_id, &id).await?,
    }
    Ok(StatusCode::NO_CONTENT)
}

// ─── OpenID Connect ──────────────────────────────────────────────────────────

/// A provider to sign in at.
#[derive(Serialize, ToSchema)]
struct ProviderButton {
    name: String,
    label: String,
}

/// The OIDC providers people may sign in at (for the sign-in page).
#[utoipa::path(get, path = "/oidc/providers", responses(
    (status = 200, body = Vec<ProviderButton>),
    (status = "5XX", body = ErrorBody),
))]
async fn oidc_providers(State(console): ConsoleState) -> Result<Json<Vec<ProviderButton>>> {
    let providers = super::oidc::providers(&console.app.pool.get().await?).await?;
    Ok(Json(providers.into_iter().map(|p| ProviderButton { name: p.name, label: p.label }).collect()))
}

/// Whether the console is set up yet.
#[derive(Serialize, ToSchema)]
struct Setup {
    /// Whether anyone has enrolled (and so can sign in). Until someone has,
    /// the sign-in page says how to make the first person, on a node.
    enrolled: bool,
}

/// Whether the console is set up yet (for the sign-in page).
#[utoipa::path(get, path = "/setup", responses(
    (status = 200, body = Setup),
    (status = "5XX", body = ErrorBody),
))]
async fn setup(State(console): ConsoleState) -> Result<Json<Setup>> {
    let enrolled = store::anyone_enrolled(&console.app.pool.get().await?).await?;
    Ok(Json(Setup { enrolled }))
}

/// Where providers send the browser back to: register it with them.
pub(super) fn redirect_uri(console: &Console) -> String {
    format!("{}/api/oidc/callback", console.party.origin)
}

#[derive(Serialize, ToSchema)]
struct OidcRedirect {
    /// Where to send the browser: the provider's sign-in.
    url: String,
}

/// Starts a sign-in at an identity source, as a directory user.
#[utoipa::path(post, path = "/oidc/{provider}/start", params(("provider" = String, Path)), responses(
    (status = 200, body = OidcRedirect),
    (status = "4XX", body = ErrorBody),
    (status = "5XX", body = ErrorBody),
))]
async fn oidc_start(State(console): ConsoleState, Path(provider): Path<String>) -> Result<Json<OidcRedirect>> {
    let client = console.app.pool.get().await?;
    let Some(provider) = super::oidc::provider(&client, &provider).await? else {
        return Err(ApiError::NotFound("no such sign-in provider".into()));
    };
    let url = super::oidc::start(&client, &provider, &redirect_uri(&console))
        .await
        .map_err(|e| ApiError::BadRequest(format!("{} can't be reached: {e:#}", provider.label)))?;
    Ok(Json(OidcRedirect { url }))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct OidcAnswer {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// A response that sends the browser to `path`, with `cookie` set.
fn redirect(path: &str, cookie: Option<axum::http::HeaderValue>) -> Response {
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, path.to_owned())]).into_response();
    if let Some(cookie) = cookie {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

/// The page to show `message` on, after a sign-in at a provider failed.
fn failed(page: &str, message: &str) -> Response {
    let message = percent_encoding::utf8_percent_encode(message, percent_encoding::NON_ALPHANUMERIC);
    redirect(&format!("{page}?error={message}"), None)
}

/// Where providers send the browser back to (register it with them): ends
/// the sign-in, as the directory user the provider vouches for, and goes on
/// to the console, replacing the browser's session if it had one. One with
/// no permission set assigned to it, or its groups, doesn't get in.
#[utoipa::path(get, path = "/oidc/callback", params(OidcAnswer), responses(
    (status = 303, description = "On to the console, signed in (or to the sign-in page, with what went wrong)"),
))]
async fn oidc_callback(State(console): ConsoleState, headers: HeaderMap, Query(answer): Query<OidcAnswer>) -> Result<Response> {
    if let Some(error) = &answer.error {
        let why = answer.error_description.as_deref().unwrap_or(error);
        return Ok(failed("/login", &format!("the provider refused the sign-in: {why}")));
    }
    let (Some(state), Some(code)) = (&answer.state, &answer.code) else {
        return Ok(failed("/login", "the provider's answer is incomplete"));
    };
    let client = console.app.pool.get().await?;
    let done = match super::oidc::finish(&client, &redirect_uri(&console), state, code).await {
        Ok(Ok(done)) => done,
        Ok(Err(why)) => return Ok(failed("/login", &why.0)),
        Err(e) => {
            eprintln!("console: a sign-in at a provider failed: {e:#}");
            return Ok(failed("/login", "the provider can't be reached; the node's log has the details"));
        }
    };
    let provider = done.provider.name.as_str();
    let name = done.name.clone().or(done.email.clone()).unwrap_or_else(|| done.subject.clone());
    let user = crate::identity_center::signed_in(
        &client,
        provider,
        &done.subject,
        &name,
        done.user_name.as_deref(),
        done.email.as_deref(),
        &done.groups,
    )
    .await?;
    let account = crate::users::account(&client).await?;
    let eligible = crate::identity_center::eligible(&client, &account, user).await?;
    if eligible.is_empty() {
        return Ok(failed(
            "/login",
            &format!("no permission set is assigned to you at {}: ask an administrator for one", done.provider.label),
        ));
    }
    // Picked for it when it has one only (one set, in one account); else it
    // picks.
    let chosen = match eligible.as_slice() {
        [only] => Some((only.set.id, only.account.as_str())),
        _ => None,
    };
    if let Some(old) = session_token(&headers) {
        store::end_session(&client, &old).await?;
    }
    let token = store::create_directory_session(&client, &account, user, chosen, None).await?;
    Ok(redirect("/", Some(session_cookie(&token))))
}
