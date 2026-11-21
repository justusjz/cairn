//! The access portal end to end, through the console's router: the AWS
//! CLI's two ways of signing in (a device code, an authorization code with
//! PKCE), refreshing, the portal's accounts, roles and credentials, and
//! what ends a sign-in.

use std::sync::Arc;

use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use ring::digest;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::super::e2e::{ADMIN, console_of, directory_user};
use super::super::{Console, router};
use super::{resolved_start_url, start_url};
use crate::users::Principal;

/// What a program (the CLI, an SDK) sends: no cookie, no `Origin`. Its
/// status, headers, and body as JSON (`null` if it isn't).
async fn call(
    console: &Arc<Console>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Value) {
    let mut req = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    if body.is_some() {
        req = req.header(header::CONTENT_TYPE, "application/json");
    }
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let resp = router(console.clone())
        .oneshot(req.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    let (parts, body) = resp.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()));
    (parts.status, parts.headers, json)
}

/// The error type an answer says it is.
fn error_type(headers: &HeaderMap) -> &str {
    headers
        .get("x-amzn-errortype")
        .map(|v| v.to_str().unwrap())
        .unwrap_or("")
}

async fn post(console: &Arc<Console>, path: &str, body: Value) -> (StatusCode, HeaderMap, Value) {
    call(console, "POST", path, &[], Some(body)).await
}

/// A portal request with access token `token`.
async fn portal(
    console: &Arc<Console>,
    method: &str,
    path: &str,
    token: &str,
) -> (StatusCode, HeaderMap, Value) {
    call(
        console,
        method,
        path,
        &[("x-amz-sso_bearer_token", token)],
        None,
    )
    .await
}

/// Registers a client as the CLI does for the device code (no grant
/// types): its ID and secret.
async fn register_device_client(console: &Arc<Console>) -> (String, String) {
    let (status, _, client) = post(
        console,
        "/client/register",
        json!({ "clientName": "botocore-client-cairn", "clientType": "public", "scopes": ["sso:account:access"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{client}");
    (
        client["clientId"].as_str().unwrap().to_owned(),
        client["clientSecret"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn the_cli_signs_in_with_a_device_code_and_gets_credentials() {
    let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
        return;
    };
    let console = console_of(&app);
    let db = app.pool.get().await.unwrap();
    let account = crate::users::account(&db).await.unwrap();
    let (mut ada, _) = directory_user(&console, "ada", ADMIN).await;

    // The start URL sends the CLI's check to an AWS-owned URL, and a
    // browser to the console.
    let (status, headers, _) = call(&console, "HEAD", "/start", &[], None).await;
    assert_eq!(status, StatusCode::FOUND);
    let resolved = resolved_start_url(&console);
    assert_eq!(headers[header::LOCATION], resolved.as_str());
    assert_eq!(
        resolved,
        "https://identitycenter.amazonaws.com/cairn/console.example.com"
    );
    let (status, headers, _) = call(
        &console,
        "GET",
        "/start",
        &[("accept", "text/html,*/*")],
        None,
    )
    .await;
    assert_eq!(
        (status, &headers[header::LOCATION]),
        (StatusCode::SEE_OTHER, &"/".parse().unwrap())
    );

    // A client registers, and asks for a device code, for this portal's start
    // URL only.
    let (client_id, secret) = register_device_client(&console).await;
    let (status, headers, _) = post(
        &console,
        "/client/register",
        json!({ "clientName": "x", "clientType": "public", "scopes": ["codewhisperer:completions"] }),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidScopeException")
    );
    let ask =
        |start: &str| json!({ "clientId": client_id, "clientSecret": secret, "startUrl": start });
    let (status, headers, err) = post(
        &console,
        "/device_authorization",
        ask("https://other.awsapps.com/start"),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidRequestException"),
        "{err}"
    );
    assert_eq!(err["error"], "invalid_request");
    let (status, headers, _) = post(
        &console,
        "/device_authorization",
        json!({ "clientId": client_id, "clientSecret": "wrong", "startUrl": resolved }),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::UNAUTHORIZED, "InvalidClientException")
    );
    let (status, _, device) = post(&console, "/device_authorization", ask(&resolved)).await;
    assert_eq!(status, StatusCode::OK, "{device}");
    let user_code = device["userCode"].as_str().unwrap().to_owned();
    assert_eq!(
        device["verificationUri"],
        "https://console.example.com/device"
    );
    assert_eq!(
        device["verificationUriComplete"],
        format!("https://console.example.com/device?user_code={user_code}")
    );
    // As the configured start URL, too (an SDK's own sign-in, without the
    // CLI's check).
    assert_eq!(
        post(&console, "/device_authorization", ask(&start_url(&console)))
            .await
            .0,
        StatusCode::OK
    );

    // Until the person allows it, the CLI waits.
    let poll = json!({
        "clientId": client_id, "clientSecret": secret,
        "grantType": "urn:ietf:params:oauth:grant-type:device_code", "deviceCode": device["deviceCode"],
    });
    let (status, headers, err) = post(&console, "/token", poll.clone()).await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "AuthorizationPendingException")
    );
    assert_eq!(err["error"], "authorization_pending");

    // Ada types the code as she reads it, and allows it.
    let typed = user_code.to_lowercase().replace('-', " ");
    let (status, request) = ada
        .send(
            "POST",
            "/api/sso/device",
            Some(json!({ "user_code": typed })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{request}");
    assert_eq!(
        (&request["kind"], &request["user_code"]),
        (&json!("device"), &json!(user_code))
    );
    assert_eq!(request["client_name"], "botocore-client-cairn");
    assert_eq!(request["session_hours"], 8);
    assert_eq!(
        ada.send(
            "POST",
            "/api/sso/device",
            Some(json!({ "user_code": "BCDF-GHJK" }))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let decide = format!("/api/sso/requests/{}", request["id"].as_str().unwrap());
    let (status, decided) = ada
        .send("POST", &decide, Some(json!({ "allow": true })))
        .await;
    assert_eq!(
        (status, &decided["redirect"]),
        (StatusCode::OK, &Value::Null),
        "{decided}"
    );
    // Once.
    assert_eq!(
        ada.send("POST", &decide, Some(json!({ "allow": false })))
            .await
            .0,
        StatusCode::NOT_FOUND
    );

    // The CLI's next poll gets the tokens; the one after that, nothing.
    let (status, _, tokens) = post(&console, "/token", poll.clone()).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["tokenType"], "Bearer");
    let expires_in = tokens["expiresIn"].as_i64().unwrap();
    assert!((3590..=3600).contains(&expires_in), "{tokens}");
    let access = tokens["accessToken"].as_str().unwrap().to_owned();
    let refresh = tokens["refreshToken"].as_str().unwrap().to_owned();
    let (status, headers, _) = post(&console, "/token", poll).await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidGrantException")
    );

    // The portal: Ada's account, her permission set as a role there, and its
    // credentials.
    let (status, _, accounts) = portal(
        &console,
        "GET",
        "/assignment/accounts?max_result=10",
        &access,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accounts}");
    assert_eq!(accounts["accountList"].as_array().unwrap().len(), 1);
    assert_eq!(accounts["accountList"][0]["accountId"], account.as_str());
    let (status, _, roles) = portal(
        &console,
        "GET",
        &format!("/assignment/roles?account_id={account}"),
        &access,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    assert_eq!(
        roles["roleList"],
        json!([{ "roleName": "ada", "accountId": account }])
    );
    let credentials = format!("/federation/credentials?account_id={account}&role_name=ada");
    let (status, _, creds) = portal(&console, "GET", &credentials, &access).await;
    assert_eq!(status, StatusCode::OK, "{creds}");
    let creds = &creds["roleCredentials"];
    let expiration = creds["expiration"].as_u64().unwrap();
    let now = crate::sessions::now() * 1000;
    assert!(
        expiration > now + 3_590_000 && expiration <= now + 3_600_000,
        "{creds}"
    );
    let session = Principal::authenticate(
        &db,
        &app.sessions,
        creds["accessKeyId"].as_str().unwrap(),
        creds["sessionToken"].as_str(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(session.arn().ends_with("/ada"), "{}", session.arn());
    assert!(
        session
            .principal_arn()
            .contains("/aws-reserved/sso.amazonaws.com/AWSReservedSSO_ada_")
    );

    // What isn't hers, or without a token.
    let (status, headers, _) = portal(
        &console,
        "GET",
        &format!("/federation/credentials?account_id={account}&role_name=other"),
        &access,
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::NOT_FOUND, "ResourceNotFoundException")
    );
    let (status, headers, err) = call(&console, "GET", &credentials, &[], None).await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::UNAUTHORIZED, "UnauthorizedException")
    );
    assert!(
        err["message"].as_str().unwrap().contains("access token"),
        "{err}"
    );
    assert_eq!(
        portal(&console, "GET", &credentials, "made-up").await.0,
        StatusCode::UNAUTHORIZED
    );

    // A refresh: a new access token, the same refresh token; both work.
    let refresh_body = json!({
        "clientId": client_id, "clientSecret": secret, "grantType": "refresh_token", "refreshToken": refresh,
    });
    let (status, _, refreshed) = post(&console, "/token", refresh_body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{refreshed}");
    assert_eq!(refreshed["refreshToken"], refresh.as_str());
    let second = refreshed["accessToken"].as_str().unwrap().to_owned();
    assert_ne!(second, access);
    for token in [&access, &second] {
        assert_eq!(
            portal(&console, "GET", &credentials, token).await.0,
            StatusCode::OK
        );
    }
    // Another client can't use it.
    let (other_id, other_secret) = register_device_client(&console).await;
    let (status, headers, _) = post(
        &console,
        "/token",
        json!({ "clientId": other_id, "clientSecret": other_secret, "grantType": "refresh_token", "refreshToken": refresh }),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidGrantException")
    );

    // Her assignment goes: so do her accounts, and new credentials.
    db.execute("DELETE FROM permission_set_assignments", &[])
        .await
        .unwrap();
    let (_, _, accounts) = portal(&console, "GET", "/assignment/accounts", &second).await;
    assert_eq!(accounts["accountList"], json!([]));
    assert_eq!(
        portal(&console, "GET", &credentials, &second).await.0,
        StatusCode::NOT_FOUND
    );

    // Signing out ends the grant: its access tokens and its refresh token.
    let (status, _, _) = portal(&console, "POST", "/logout", &second).await;
    assert_eq!(status, StatusCode::OK);
    for token in [&access, &second] {
        assert_eq!(
            portal(&console, "GET", "/assignment/accounts", token)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, headers, _) = post(&console, "/token", refresh_body).await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidGrantException")
    );

    // The root user has no permission sets to allow sign-ins with.
    let (_, _, device) = post(&console, "/device_authorization", ask(&resolved)).await;
    let token = crate::console::store::create_root_link(&db, &account)
        .await
        .unwrap();
    let root_session = crate::console::store::root_sign_in(&db, &token)
        .await
        .unwrap()
        .unwrap();
    let (status, _, err) = call(
        &console,
        "POST",
        "/api/sso/device",
        &[
            ("cookie", &format!("__Host-cairn-session={root_session}")),
            ("origin", "https://console.example.com"),
            ("x-cairn-ui", "1"),
        ],
        Some(json!({ "user_code": device["userCode"] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err}");
}

#[tokio::test]
async fn the_cli_signs_in_with_a_browser_and_pkce() {
    let Some(app) = crate::e2e::node_with(crate::packer::Config::default(), None).await else {
        return;
    };
    let console = console_of(&app);
    let db = app.pool.get().await.unwrap();
    let (mut ada, _) = directory_user(&console, "ada", ADMIN).await;
    let resolved = resolved_start_url(&console);

    // The CLI registers for the authorization code, with its loopback
    // redirect URI (no port), and the start URL as it resolved it.
    let registration = |uri: &str| {
        json!({
            "clientName": "botocore-client-cairn", "clientType": "public",
            "grantTypes": ["authorization_code", "refresh_token"],
            "redirectUris": [uri], "issuerUrl": resolved, "scopes": ["sso:account:access"],
        })
    };
    let (status, headers, _) = post(
        &console,
        "/client/register",
        registration("https://evil.example.com/cb"),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidRequestException")
    );
    let (status, _, client) = post(
        &console,
        "/client/register",
        registration("http://127.0.0.1/oauth/callback"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{client}");
    let client_id = client["clientId"].as_str().unwrap().to_owned();
    let secret = client["clientSecret"].as_str().unwrap().to_owned();
    assert_eq!(
        client["authorizationEndpoint"],
        "https://console.example.com/authorize"
    );
    // A client that registered for this grant only can't use a device code.
    let (status, headers, _) = post(
        &console,
        "/device_authorization",
        json!({ "clientId": client_id, "clientSecret": secret, "startUrl": resolved }),
    )
    .await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "UnauthorizedClientException")
    );

    let verifier = "a9g6XCPhuc1nFGWgBwVBTw5eKd55ZhtsFzwDebqwmGmXfmpr0H_fTr3Uuqz9ZuuT";
    let challenge = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, verifier.as_bytes()));
    let callback = "http://127.0.0.1:41709/oauth/callback";
    let authorize = |redirect: &str| {
        format!(
            "/authorize?response_type=code&client_id={client_id}&redirect_uri={}&state=st%20ate\
             &code_challenge={challenge}&code_challenge_method=S256&scopes=sso%3Aaccount%3Aaccess",
            super::encode(redirect)
        )
    };
    // Where to send the browser back to must be the client's: else it's not
    // sent anywhere.
    let (status, _, page) = call(
        &console,
        "GET",
        &authorize("http://127.0.0.1:41709/elsewhere"),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        page.as_str().unwrap().contains("isn't the client's"),
        "{page}"
    );

    // The person signs in, and allows it (or not): the browser goes back to
    // the CLI, with the code (or why not), and the state.
    let pending = || async {
        let (status, headers, _) = call(&console, "GET", &authorize(callback), &[], None).await;
        assert_eq!(status, StatusCode::FOUND);
        let page = headers[header::LOCATION].to_str().unwrap().to_owned();
        assert!(page.starts_with("/sso/authorize/"), "{page}");
        page.rsplit('/').next().unwrap().to_owned()
    };
    let decide = async |ada: &mut super::super::e2e::Browser, id: &str, allow: bool| {
        let (status, request) = ada
            .send("GET", &format!("/api/sso/requests/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{request}");
        assert_eq!(request["kind"], "code");
        let (status, decided) = ada
            .send(
                "POST",
                &format!("/api/sso/requests/{id}"),
                Some(json!({ "allow": allow })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{decided}");
        decided["redirect"].as_str().unwrap().to_owned()
    };
    let id = pending().await;
    let back = decide(&mut ada, &id, false).await;
    assert_eq!(
        back,
        format!(
            "{callback}?error=access_denied&error_description=you%20denied%20the%20sign-in&state=st%20ate"
        )
    );
    let code_of = |back: &str| {
        let query = back.strip_prefix(&format!("{callback}?code=")).unwrap();
        let (code, state) = query.split_once('&').unwrap();
        assert_eq!(state, "state=st%20ate");
        code.to_owned()
    };
    let exchange = |code: &str, verifier: &str, redirect: &str| {
        json!({
            "clientId": client_id, "clientSecret": secret, "grantType": "authorization_code",
            "code": code, "codeVerifier": verifier, "redirectUri": redirect,
        })
    };

    // A wrong verifier gets nothing, and uses the code up.
    let code = code_of(&decide(&mut ada, &pending().await, true).await);
    let wrong = "b".repeat(43);
    let (status, headers, _) = post(&console, "/token", exchange(&code, &wrong, callback)).await;
    assert_eq!(
        (status, error_type(&headers)),
        (StatusCode::BAD_REQUEST, "InvalidGrantException")
    );
    let (status, _, _) = post(&console, "/token", exchange(&code, verifier, callback)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // As does another redirect URI than the authorization's.
    let code = code_of(&decide(&mut ada, &pending().await, true).await);
    let (status, _, _) = post(
        &console,
        "/token",
        exchange(&code, verifier, "http://127.0.0.1:1/oauth/callback"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The right ones get the tokens.
    let code = code_of(&decide(&mut ada, &pending().await, true).await);
    let (status, _, tokens) = post(&console, "/token", exchange(&code, verifier, callback)).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    let access = tokens["accessToken"].as_str().unwrap().to_owned();
    assert_eq!(
        portal(&console, "GET", "/assignment/accounts", &access)
            .await
            .0,
        StatusCode::OK
    );

    // A page that's finished, or never was, is gone.
    assert_eq!(
        ada.send("GET", &format!("/api/sso/requests/{id}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        ada.send("GET", "/api/sso/requests/nonsense", None).await.0,
        StatusCode::NOT_FOUND
    );
    // Without a session, there's nothing to allow it with.
    let (status, _, _) = call(
        &console,
        "GET",
        &format!("/api/sso/requests/{}", pending().await),
        &[],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A grant lasts `sso-session-hours`: past it, neither its refresh token
    // nor its access tokens work, and the reaper takes it.
    let refresh = json!({
        "clientId": client_id, "clientSecret": secret, "grantType": "refresh_token",
        "refreshToken": tokens["refreshToken"],
    });
    assert_eq!(
        post(&console, "/token", refresh.clone()).await.0,
        StatusCode::OK
    );
    let hours: i32 = db
        .query_one(
            "SELECT extract(epoch FROM expires_at - created_at)::int / 3600 FROM sso_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(hours, 8);
    db.execute("UPDATE sso_grants SET expires_at = now()", &[])
        .await
        .unwrap();
    assert_eq!(
        post(&console, "/token", refresh).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        portal(&console, "GET", "/assignment/accounts", &access)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(super::reap(&db).await.unwrap() >= 1);
    let grants: i64 = db
        .query_one("SELECT count(*) FROM sso_grants", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(grants, 0);

    // A user that's deleted takes its grants along.
    let code = code_of(&decide(&mut ada, &pending().await, true).await);
    let (_, _, tokens) = post(&console, "/token", exchange(&code, verifier, callback)).await;
    db.execute("DELETE FROM identity_users WHERE user_name = 'ada'", &[])
        .await
        .unwrap();
    let access = tokens["accessToken"].as_str().unwrap();
    assert_eq!(
        portal(&console, "GET", "/assignment/accounts", access)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
