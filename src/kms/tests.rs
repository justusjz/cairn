//! The KMS end to end, against a real Postgres, with a file root key: its
//! API as users and roots call it, keys' policies and identity policies
//! together, keys' states, rotation and scheduled deletion, aliases and
//! tags; and the root key's canary, and the keys it wraps.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, Method};
use serde_json::{Value, json};

use super::{Api, Params};
use crate::{
    App,
    e2e::kms_node,
    s3::access::{Access, Origin},
    users::Principal,
};

/// What a request answered: its result, or its error's type and message.
type Answer = Result<Value, (String, String)>;

async fn call(app: &Arc<App>, principal: &Principal, operation: &str, params: Value) -> Answer {
    let client = app.pool.get().await.unwrap();
    let origin = Origin {
        peer: Some("127.0.0.1".parse().unwrap()),
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(principal),
        &principal.account,
        &Method::POST,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let Value::Object(params) = params else {
        panic!("params are an object")
    };
    let mut api = Api {
        kms: app.kms.as_ref().unwrap(),
        client: &client,
        principal,
        access: &access,
        params: Params(params),
        touched: Default::default(),
    };
    api.dispatch(operation)
        .await
        .map_err(|e| (e.kind.to_owned(), e.message))
}

fn ok(answer: Answer) -> Value {
    answer.unwrap_or_else(|(kind, message)| panic!("{kind}: {message}"))
}

fn refused(answer: Answer, kind: &str) -> String {
    match answer {
        Ok(value) => panic!("not refused: {value}"),
        Err((k, message)) => {
            assert_eq!(k, kind, "{message}");
            message
        }
    }
}

/// A new user `name`, with the identity policy `statements` (none if
/// empty).
async fn user(app: &Arc<App>, name: &str, statements: &str) -> Principal {
    let client = app.pool.get().await.unwrap();
    let account = crate::users::account(&client).await.unwrap();
    let (key, _) = crate::users::create_for(&client, &account, name, None, false)
        .await
        .unwrap();
    if !statements.is_empty() {
        let policy = format!(r#"{{"Version":"2012-10-17","Statement":[{statements}]}}"#);
        crate::users::put_policy(&client, &account, name, "p", &policy)
            .await
            .unwrap();
    }
    Principal::load(&client, &key).await.unwrap().unwrap()
}

/// A user that may do anything with KMS keys (as its identity policy
/// says; keys' default policies leave that to it).
async fn admin(app: &Arc<App>) -> Principal {
    user(
        app,
        "kms-admin",
        r#"{"Effect":"Allow","Action":"kms:*","Resource":"*"}"#,
    )
    .await
}

/// A new key's ID and ARN, made by `who`.
async fn key(app: &Arc<App>, who: &Principal, params: Value) -> (String, String) {
    let made = ok(call(app, who, "CreateKey", params).await);
    let metadata = &made["KeyMetadata"];
    (
        metadata["KeyId"].as_str().unwrap().to_owned(),
        metadata["Arn"].as_str().unwrap().to_owned(),
    )
}

fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

/// Keys are made with KMS's metadata, described by their IDs, ARNs and
/// aliases, and listed a page at a time; a key that isn't there, or isn't
/// one, is KMS's NotFoundException.
#[tokio::test]
async fn keys_are_made_described_and_listed() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let made = ok(call(&app, &admin, "CreateKey", json!({ "Description": "first" })).await);
    let metadata = &made["KeyMetadata"];
    let id = metadata["KeyId"].as_str().unwrap().to_owned();
    let arn = metadata["Arn"].as_str().unwrap().to_owned();
    assert_eq!(
        arn,
        crate::kms::keys::key_arn(&admin.account, id.parse().unwrap())
    );
    assert_eq!(metadata["KeyState"], "Enabled");
    assert_eq!(metadata["Enabled"], true);
    assert_eq!(metadata["KeyManager"], "CUSTOMER");
    assert_eq!(metadata["KeySpec"], "SYMMETRIC_DEFAULT");
    assert_eq!(metadata["KeyUsage"], "ENCRYPT_DECRYPT");
    assert_eq!(metadata["Description"], "first");
    // Its default policy, which leaves it to the account.
    let policy = ok(call(&app, &admin, "GetKeyPolicy", json!({ "KeyId": id })).await);
    assert!(
        policy["Policy"]
            .as_str()
            .unwrap()
            .contains(&format!("arn:aws:iam::{}:root", admin.account))
    );
    ok(call(
        &app,
        &admin,
        "CreateAlias",
        json!({ "AliasName": "alias/first", "TargetKeyId": id }),
    )
    .await);
    for given in [id.as_str(), arn.as_str(), "alias/first"] {
        let described = ok(call(&app, &admin, "DescribeKey", json!({ "KeyId": given })).await);
        assert_eq!(described["KeyMetadata"]["KeyId"], id.as_str());
    }
    let alias_arn = crate::kms::keys::alias_arn(&admin.account, "alias/first");
    ok(call(&app, &admin, "DescribeKey", json!({ "KeyId": alias_arn })).await);
    for missing in [
        "alias/nope",
        "6c3c7a2e-0a47-4a43-9c4c-3a3ad0b4b1f4",
        "transit/k",
    ] {
        refused(
            call(&app, &admin, "DescribeKey", json!({ "KeyId": missing })).await,
            "NotFoundException",
        );
    }
    // Only symmetric keys of KMS's own.
    refused(
        call(&app, &admin, "CreateKey", json!({ "KeySpec": "RSA_2048" })).await,
        "UnsupportedOperationException",
    );
    let (second, _) = key(&app, &admin, json!({})).await;
    let first_page = ok(call(&app, &admin, "ListKeys", json!({ "Limit": 1 })).await);
    assert_eq!(first_page["Truncated"], true);
    let marker = first_page["NextMarker"].as_str().unwrap();
    let second_page = ok(call(
        &app,
        &admin,
        "ListKeys",
        json!({ "Limit": 1, "Marker": marker }),
    )
    .await);
    assert_eq!(second_page["Truncated"], false);
    let mut listed: Vec<&str> = [&first_page, &second_page]
        .iter()
        .map(|page| page["Keys"][0]["KeyId"].as_str().unwrap())
        .collect();
    listed.sort();
    let mut expected = vec![id.as_str(), second.as_str()];
    expected.sort();
    assert_eq!(listed, expected);
}

/// What a key encrypts opens with its encryption context alone, and names
/// its key; data keys come with their plaintext or without, and re-encrypt
/// under another key. Random bytes are random.
#[tokio::test]
async fn keys_encrypt_and_decrypt() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let (id, arn) = key(&app, &admin, json!({})).await;
    let (other, other_arn) = key(&app, &admin, json!({})).await;
    let context = json!({ "purpose": "test", "n": "1" });
    let encrypted = ok(call(
        &app,
        &admin,
        "Encrypt",
        json!({ "KeyId": id, "Plaintext": b64(b"secret"), "EncryptionContext": context }),
    )
    .await);
    assert_eq!(encrypted["KeyId"], arn.as_str());
    let blob = encrypted["CiphertextBlob"].as_str().unwrap().to_owned();
    let decrypted = ok(call(
        &app,
        &admin,
        "Decrypt",
        json!({ "CiphertextBlob": blob, "EncryptionContext": context }),
    )
    .await);
    assert_eq!(decrypted["Plaintext"], b64(b"secret"));
    assert_eq!(decrypted["KeyId"], arn.as_str());
    // Not with another context, or none; and not as another key's.
    for wrong in [json!({ "purpose": "test" }), json!({})] {
        refused(
            call(
                &app,
                &admin,
                "Decrypt",
                json!({ "CiphertextBlob": blob, "EncryptionContext": wrong }),
            )
            .await,
            "InvalidCiphertextException",
        );
    }
    refused(
        call(
            &app,
            &admin,
            "Decrypt",
            json!({ "CiphertextBlob": blob, "EncryptionContext": context, "KeyId": other }),
        )
        .await,
        "IncorrectKeyException",
    );
    let mut broken = STANDARD.decode(&blob).unwrap();
    *broken.last_mut().unwrap() ^= 1;
    refused(
        call(
            &app,
            &admin,
            "Decrypt",
            json!({ "CiphertextBlob": b64(&broken), "EncryptionContext": context }),
        )
        .await,
        "InvalidCiphertextException",
    );
    refused(
        call(
            &app,
            &admin,
            "Decrypt",
            json!({ "CiphertextBlob": b64(b"not a ciphertext of the KMS's at all") }),
        )
        .await,
        "InvalidCiphertextException",
    );

    // Data keys.
    let generated = ok(call(
        &app,
        &admin,
        "GenerateDataKey",
        json!({ "KeyId": id, "KeySpec": "AES_256" }),
    )
    .await);
    let plaintext = STANDARD
        .decode(generated["Plaintext"].as_str().unwrap())
        .unwrap();
    assert_eq!(plaintext.len(), 32);
    let opened = ok(call(
        &app,
        &admin,
        "Decrypt",
        json!({ "CiphertextBlob": generated["CiphertextBlob"] }),
    )
    .await);
    assert_eq!(opened["Plaintext"], generated["Plaintext"]);
    let without = ok(call(
        &app,
        &admin,
        "GenerateDataKeyWithoutPlaintext",
        json!({ "KeyId": id, "NumberOfBytes": 16 }),
    )
    .await);
    assert!(without.get("Plaintext").is_none());
    let opened = ok(call(
        &app,
        &admin,
        "Decrypt",
        json!({ "CiphertextBlob": without["CiphertextBlob"] }),
    )
    .await);
    assert_eq!(
        STANDARD
            .decode(opened["Plaintext"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    refused(
        call(
            &app,
            &admin,
            "GenerateDataKey",
            json!({ "KeyId": id, "KeySpec": "AES_256", "NumberOfBytes": 32 }),
        )
        .await,
        "ValidationException",
    );

    // Re-encrypted under the other key, with another context.
    let moved = ok(call(
        &app,
        &admin,
        "ReEncrypt",
        json!({
            "CiphertextBlob": blob,
            "SourceEncryptionContext": context,
            "DestinationKeyId": other_arn,
            "DestinationEncryptionContext": { "moved": "yes" },
        }),
    )
    .await);
    assert_eq!(moved["SourceKeyId"], arn.as_str());
    assert_eq!(moved["KeyId"], other_arn.as_str());
    let opened = ok(call(
        &app,
        &admin,
        "Decrypt",
        json!({ "CiphertextBlob": moved["CiphertextBlob"], "EncryptionContext": { "moved": "yes" } }),
    )
    .await);
    assert_eq!(opened["Plaintext"], b64(b"secret"));

    // DryRun: allowed, but not done.
    refused(
        call(
            &app,
            &admin,
            "Encrypt",
            json!({ "KeyId": id, "Plaintext": b64(b"x"), "DryRun": true }),
        )
        .await,
        "DryRunOperationException",
    );
    let random = ok(call(
        &app,
        &admin,
        "GenerateRandom",
        json!({ "NumberOfBytes": 64 }),
    )
    .await);
    assert_eq!(
        STANDARD
            .decode(random["Plaintext"].as_str().unwrap())
            .unwrap()
            .len(),
        64
    );
    refused(
        call(
            &app,
            &admin,
            "GenerateRandom",
            json!({ "NumberOfBytes": 0 }),
        )
        .await,
        "ValidationException",
    );
}

/// Who may use a key, as KMS decides it: its policy must allow it, by
/// naming the principal (then nothing else need), or the account (then
/// the principal's identity policies decide); a Deny in either denies. A
/// key's policy that would lock its caller out is refused, unless the
/// caller says to bypass that check. An account's root user may do what
/// the key's policy lets the account do.
#[tokio::test]
async fn policies_decide_who_uses_keys() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let alice = user(
        &app,
        "alice",
        r#"{"Effect":"Allow","Action":["kms:Encrypt","kms:Decrypt"],"Resource":"*"}"#,
    )
    .await;
    let bob = user(&app, "bob", "").await;
    let (id, arn) = key(&app, &admin, json!({})).await;
    let encrypt = json!({ "KeyId": id, "Plaintext": b64(b"x") });
    // The default policy leaves it to identity policies: Alice's allow it,
    // Bob has none.
    ok(call(&app, &alice, "Encrypt", encrypt.clone()).await);
    let message = refused(
        call(&app, &bob, "Encrypt", encrypt.clone()).await,
        "AccessDeniedException",
    );
    assert!(
        message.contains("kms:Encrypt") && message.contains(&arn),
        "{message}"
    );
    refused(
        call(&app, &bob, "DescribeKey", json!({ "KeyId": id })).await,
        "AccessDeniedException",
    );
    // Nor may Alice do what her policy doesn't say.
    refused(
        call(
            &app,
            &alice,
            "GenerateDataKey",
            json!({ "KeyId": id, "KeySpec": "AES_256" }),
        )
        .await,
        "AccessDeniedException",
    );
    let root = Principal::root(&admin.account);
    ok(call(&app, &root, "Encrypt", encrypt.clone()).await);

    // A policy naming Bob lets him, whatever his own; one denying Alice
    // denies her, whatever hers.
    let policy = |extra: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[
                {{"Sid":"account","Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"kms:*","Resource":"*"}},
                {{"Sid":"bob","Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:user/bob"}},"Action":"kms:Encrypt","Resource":"*"}}{extra}]}}"#,
            account = admin.account
        )
    };
    let deny_alice = format!(
        r#",{{"Effect":"Deny","Principal":{{"AWS":"arn:aws:iam::{}:user/alice"}},"Action":"kms:Encrypt","Resource":"*"}}"#,
        admin.account
    );
    ok(call(
        &app,
        &admin,
        "PutKeyPolicy",
        json!({ "KeyId": id, "Policy": policy(&deny_alice) }),
    )
    .await);
    ok(call(&app, &bob, "Encrypt", encrypt.clone()).await);
    refused(
        call(&app, &alice, "Encrypt", encrypt.clone()).await,
        "AccessDeniedException",
    );
    // Conditions on the encryption context.
    let conditioned = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:root"}},"Action":"kms:*","Resource":"*"}},
            {{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{account}:user/bob"}},"Action":"kms:Encrypt","Resource":"*",
              "Condition":{{"StringEquals":{{"kms:EncryptionContext:team":"blue"}}}}}}]}}"#,
        account = admin.account
    );
    ok(call(
        &app,
        &admin,
        "PutKeyPolicy",
        json!({ "KeyId": id, "Policy": conditioned }),
    )
    .await);
    refused(
        call(&app, &bob, "Encrypt", encrypt.clone()).await,
        "AccessDeniedException",
    );
    ok(call(
        &app,
        &bob,
        "Encrypt",
        json!({ "KeyId": id, "Plaintext": b64(b"x"), "EncryptionContext": { "team": "blue" } }),
    )
    .await);

    // A policy that would lock the admin out, unless the check is bypassed.
    let lockout = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{}:user/bob"}},"Action":"kms:*","Resource":"*"}}]}}"#,
        admin.account
    );
    refused(
        call(
            &app,
            &admin,
            "PutKeyPolicy",
            json!({ "KeyId": id, "Policy": lockout }),
        )
        .await,
        "MalformedPolicyDocumentException",
    );
    refused(
        call(
            &app,
            &admin,
            "PutKeyPolicy",
            json!({ "KeyId": id, "Policy": r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Principal":"*","Resource":"*"}]}"# }),
        )
        .await,
        "MalformedPolicyDocumentException",
    );
    ok(call(
        &app,
        &admin,
        "PutKeyPolicy",
        json!({ "KeyId": id, "Policy": lockout, "BypassPolicyLockoutSafetyCheck": true }),
    )
    .await);
    refused(
        call(&app, &admin, "DescribeKey", json!({ "KeyId": id })).await,
        "AccessDeniedException",
    );
    // Not even the root user, then: as in AWS.
    refused(
        call(&app, &root, "Encrypt", encrypt).await,
        "AccessDeniedException",
    );
    // Actions on no key are the identity policies'.
    refused(
        call(&app, &bob, "CreateKey", json!({})).await,
        "AccessDeniedException",
    );
    refused(
        call(&app, &bob, "ListKeys", json!({})).await,
        "AccessDeniedException",
    );
}

/// A disabled key encrypts and decrypts nothing until it's enabled again;
/// one scheduled for deletion nothing, until that's cancelled (it's
/// disabled then), or it's deleted: then nothing it encrypted opens again.
#[tokio::test]
async fn keys_are_disabled_and_deleted() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let (id, _) = key(&app, &admin, json!({})).await;
    let blob = ok(call(
        &app,
        &admin,
        "Encrypt",
        json!({ "KeyId": id, "Plaintext": b64(b"x") }),
    )
    .await)["CiphertextBlob"]
        .clone();
    let decrypt = json!({ "CiphertextBlob": blob });
    ok(call(&app, &admin, "DisableKey", json!({ "KeyId": id })).await);
    refused(
        call(&app, &admin, "Decrypt", decrypt.clone()).await,
        "DisabledException",
    );
    refused(
        call(
            &app,
            &admin,
            "Encrypt",
            json!({ "KeyId": id, "Plaintext": b64(b"x") }),
        )
        .await,
        "DisabledException",
    );
    ok(call(&app, &admin, "EnableKey", json!({ "KeyId": id })).await);
    ok(call(&app, &admin, "Decrypt", decrypt.clone()).await);

    refused(
        call(
            &app,
            &admin,
            "ScheduleKeyDeletion",
            json!({ "KeyId": id, "PendingWindowInDays": 3 }),
        )
        .await,
        "ValidationException",
    );
    let scheduled = ok(call(
        &app,
        &admin,
        "ScheduleKeyDeletion",
        json!({ "KeyId": id, "PendingWindowInDays": 7 }),
    )
    .await);
    assert_eq!(scheduled["KeyState"], "PendingDeletion");
    let in_days = (scheduled["DeletionDate"].as_f64().unwrap()
        - std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64())
        / 86_400.0;
    assert!((6.9..7.1).contains(&in_days), "{in_days}");
    refused(
        call(&app, &admin, "Decrypt", decrypt.clone()).await,
        "KMSInvalidStateException",
    );
    refused(
        call(&app, &admin, "EnableKey", json!({ "KeyId": id })).await,
        "KMSInvalidStateException",
    );
    ok(call(&app, &admin, "CancelKeyDeletion", json!({ "KeyId": id })).await);
    let described = ok(call(&app, &admin, "DescribeKey", json!({ "KeyId": id })).await);
    assert_eq!(described["KeyMetadata"]["KeyState"], "Disabled");
    refused(
        call(&app, &admin, "CancelKeyDeletion", json!({ "KeyId": id })).await,
        "KMSInvalidStateException",
    );

    ok(call(&app, &admin, "ScheduleKeyDeletion", json!({ "KeyId": id })).await);
    // Not yet due: the key stays.
    crate::kms::keys::maintain(app.kms.as_ref().unwrap(), &app.pool)
        .await
        .unwrap();
    ok(call(&app, &admin, "DescribeKey", json!({ "KeyId": id })).await);
    // Due.
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE kms_keys SET deletion_date = now() - interval '1 second' WHERE id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap();
    crate::kms::keys::maintain(app.kms.as_ref().unwrap(), &app.pool)
        .await
        .unwrap();
    refused(
        call(&app, &admin, "DescribeKey", json!({ "KeyId": id })).await,
        "NotFoundException",
    );
    refused(
        call(&app, &admin, "Decrypt", decrypt).await,
        "InvalidCiphertextException",
    );
    assert_eq!(
        crate::e2e::query_i64(&app, "SELECT count(*) FROM kms_key_versions").await,
        0,
        "its material is gone"
    );
}

/// Rotating a key, on demand or on its schedule, makes a new version that
/// encrypts from then on; what older ones encrypted still opens.
#[tokio::test]
async fn keys_rotate() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let (id, _) = key(&app, &admin, json!({})).await;
    let encrypt = || {
        let (app, admin, id) = (app.clone(), &admin, id.clone());
        async move {
            let blob = ok(call(
                &app,
                admin,
                "Encrypt",
                json!({ "KeyId": id, "Plaintext": b64(b"x") }),
            )
            .await)["CiphertextBlob"]
                .as_str()
                .unwrap()
                .to_owned();
            let (_, version) =
                crate::kms::keys::blob_key(&STANDARD.decode(&blob).unwrap()).unwrap();
            (blob, version)
        }
    };
    let (first, version) = encrypt().await;
    assert_eq!(version, 1);
    let status = ok(call(&app, &admin, "GetKeyRotationStatus", json!({ "KeyId": id })).await);
    assert_eq!(status["KeyRotationEnabled"], false);
    ok(call(&app, &admin, "RotateKeyOnDemand", json!({ "KeyId": id })).await);
    let (second, version) = encrypt().await;
    assert_eq!(version, 2);
    for blob in [&first, &second] {
        let opened = ok(call(&app, &admin, "Decrypt", json!({ "CiphertextBlob": blob })).await);
        assert_eq!(opened["Plaintext"], b64(b"x"));
    }
    ok(call(
        &app,
        &admin,
        "EnableKeyRotation",
        json!({ "KeyId": id, "RotationPeriodInDays": 90 }),
    )
    .await);
    let status = ok(call(&app, &admin, "GetKeyRotationStatus", json!({ "KeyId": id })).await);
    assert_eq!(status["KeyRotationEnabled"], true);
    assert_eq!(status["RotationPeriodInDays"], 90);
    refused(
        call(
            &app,
            &admin,
            "EnableKeyRotation",
            json!({ "KeyId": id, "RotationPeriodInDays": 30 }),
        )
        .await,
        "ValidationException",
    );
    // Due: the next pass rotates it, once.
    app.pool
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE kms_keys SET next_rotation = now() - interval '1 second' WHERE id = $1::text::uuid",
            &[&id],
        )
        .await
        .unwrap();
    crate::kms::keys::maintain(app.kms.as_ref().unwrap(), &app.pool)
        .await
        .unwrap();
    crate::kms::keys::maintain(app.kms.as_ref().unwrap(), &app.pool)
        .await
        .unwrap();
    assert_eq!(encrypt().await.1, 3);
    let rotations = ok(call(&app, &admin, "ListKeyRotations", json!({ "KeyId": id })).await);
    let kinds: Vec<&str> = rotations["Rotations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["RotationType"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["ON_DEMAND", "AUTOMATIC"]);
    // A node that just started unwraps every version again.
    app.kms.as_ref().unwrap().forget();
    for blob in [&first, &second] {
        ok(call(&app, &admin, "Decrypt", json!({ "CiphertextBlob": blob })).await);
    }
}

/// Aliases name keys of their account, uniquely, never `alias/aws/…`; tags
/// are set, listed and removed, and policies see them.
#[tokio::test]
async fn aliases_and_tags() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    let (id, _) = key(
        &app,
        &admin,
        json!({ "Tags": [{ "TagKey": "team", "TagValue": "blue" }] }),
    )
    .await;
    let (other, _) = key(&app, &admin, json!({})).await;
    ok(call(
        &app,
        &admin,
        "CreateAlias",
        json!({ "AliasName": "alias/app", "TargetKeyId": id }),
    )
    .await);
    refused(
        call(
            &app,
            &admin,
            "CreateAlias",
            json!({ "AliasName": "alias/app", "TargetKeyId": other }),
        )
        .await,
        "AlreadyExistsException",
    );
    refused(
        call(
            &app,
            &admin,
            "CreateAlias",
            json!({ "AliasName": "alias/aws/mine", "TargetKeyId": other }),
        )
        .await,
        "NotAuthorizedException",
    );
    refused(
        call(
            &app,
            &admin,
            "CreateAlias",
            json!({ "AliasName": "app", "TargetKeyId": other }),
        )
        .await,
        "ValidationException",
    );
    let listed = ok(call(&app, &admin, "ListAliases", json!({ "KeyId": id })).await);
    assert_eq!(listed["Aliases"][0]["AliasName"], "alias/app");
    assert_eq!(listed["Aliases"][0]["TargetKeyId"], id.as_str());
    ok(call(
        &app,
        &admin,
        "UpdateAlias",
        json!({ "AliasName": "alias/app", "TargetKeyId": other }),
    )
    .await);
    let described = ok(call(&app, &admin, "DescribeKey", json!({ "KeyId": "alias/app" })).await);
    assert_eq!(described["KeyMetadata"]["KeyId"], other.as_str());
    ok(call(
        &app,
        &admin,
        "DeleteAlias",
        json!({ "AliasName": "alias/app" }),
    )
    .await);
    refused(
        call(&app, &admin, "DescribeKey", json!({ "KeyId": "alias/app" })).await,
        "NotFoundException",
    );

    let tags = ok(call(&app, &admin, "ListResourceTags", json!({ "KeyId": id })).await);
    assert_eq!(
        tags["Tags"],
        json!([{ "TagKey": "team", "TagValue": "blue" }])
    );
    ok(call(
        &app,
        &admin,
        "TagResource",
        json!({ "KeyId": id, "Tags": [{ "TagKey": "team", "TagValue": "red" }, { "TagKey": "env", "TagValue": "prod" }] }),
    )
    .await);
    let tags = ok(call(&app, &admin, "ListResourceTags", json!({ "KeyId": id })).await);
    assert_eq!(
        tags["Tags"],
        json!([{ "TagKey": "team", "TagValue": "red" }, { "TagKey": "env", "TagValue": "prod" }])
    );
    refused(
        call(
            &app,
            &admin,
            "TagResource",
            json!({ "KeyId": id, "Tags": [{ "TagKey": "aws:x", "TagValue": "y" }] }),
        )
        .await,
        "TagException",
    );
    // A user whose policy allows keys by their tags (ABAC).
    let carol = user(
        &app,
        "carol",
        r#"{"Effect":"Allow","Action":"kms:Encrypt","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/env":"prod"}}}"#,
    )
    .await;
    let encrypt = |key: &str| json!({ "KeyId": key, "Plaintext": b64(b"x") });
    ok(call(&app, &carol, "Encrypt", encrypt(&id)).await);
    refused(
        call(&app, &carol, "Encrypt", encrypt(&other)).await,
        "AccessDeniedException",
    );
    ok(call(
        &app,
        &admin,
        "UntagResource",
        json!({ "KeyId": id, "TagKeys": ["env"] }),
    )
    .await);
    refused(
        call(&app, &carol, "Encrypt", encrypt(&id)).await,
        "AccessDeniedException",
    );
}

/// The root key's canary: a node with another root refuses to start; one
/// with none, once the cluster has one. The keys the database kept as they
/// were are wrapped by the root, and open as before.
#[tokio::test]
async fn the_root_key_is_the_clusters() {
    let Some(app) = kms_node().await else { return };
    let kms = app.kms.as_ref().unwrap();
    // Checked again: the same root.
    kms.check_root(&app.pool).await.unwrap();
    let other =
        crate::kms::Kms::with_root(crate::kms::Root::File(zeroize::Zeroizing::new([5; 32])));
    let e = other.check_root(&app.pool).await.unwrap_err();
    assert!(e.to_string().contains("isn't the cluster's"), "{e:#}");
    let e = crate::kms::require_root(&app.pool).await.unwrap_err();
    assert!(e.to_string().contains("has none"), "{e:#}");

    // A tier's key from before the root: stored as it is, then wrapped.
    let client = app.pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO tiers (name, endpoint, region, bucket, prefix, path_style, access_key_id,
                                secret_access_key, key)
             VALUES ('old', 'http://127.0.0.1:1', 'us-east-1', 'b', 'p/', true, 'k', 's', $1)",
            &[&vec![7u8; 32]],
        )
        .await
        .unwrap();
    crate::kms::wrap_stored_keys(kms, &app.pool).await.unwrap();
    let (stored, wrapped): (Vec<u8>, bool) = {
        let row = client
            .query_one("SELECT key, key_wrapped FROM tiers WHERE name = 'old'", &[])
            .await
            .unwrap();
        (row.get(0), row.get(1))
    };
    assert!(wrapped && stored != vec![7u8; 32]);
    let tier = crate::tiers::load(&client)
        .await
        .unwrap()
        .remove("old")
        .unwrap();
    assert_eq!(*tier.open_key(&app).await.unwrap(), [7u8; 32]);
}

/// Calls `operation` as `principal`, as a request does, with its event
/// logged (see `super::audited`).
async fn call_audited(
    app: &Arc<App>,
    principal: &Principal,
    operation: &str,
    params: Value,
) -> Answer {
    let client = app.pool.get().await.unwrap();
    let origin = Origin {
        peer: Some("192.0.2.7".parse().unwrap()),
        trusted_proxies: &[],
        signed: None,
        form: false,
    };
    let access = Access::new(
        Some(principal),
        &principal.account,
        &Method::POST,
        &HeaderMap::new(),
        "",
        &origin,
    )
    .unwrap();
    let Value::Object(params) = params else {
        panic!("params are an object")
    };
    let mut event = crate::audit::Event::new(
        super::SOURCE,
        operation,
        crate::audit::identity(principal, "AKIATEST"),
        &principal.account,
        super::read_only(operation).unwrap(),
    );
    event.parameters = crate::audit::parameters(&params, super::SECRET, super::VERBATIM);
    let mut api = Api {
        kms: app.kms.as_ref().unwrap(),
        client: &client,
        principal,
        access: &access,
        params: Params(params),
        touched: Default::default(),
    };
    super::audited(&app.audit, &mut api, operation, event)
        .await
        .map_err(|e| (e.kind.to_owned(), e.message))
}

/// Every operation Cairn has is dispatched, and audited as one.
#[tokio::test]
async fn every_operation_is_dispatched() {
    let Some(app) = kms_node().await else { return };
    let admin = admin(&app).await;
    for (operation, _) in super::OPERATIONS {
        if let Err((kind, message)) = call(&app, &admin, operation, json!({})).await {
            assert_ne!(kind, "UnknownOperationException", "{operation}: {message}");
        }
    }
    assert_eq!(super::read_only("Frobnicate"), None);
    assert_eq!(super::read_only("CreateGrant"), Some(false));
}

/// KMS's calls are logged as CloudTrail's events, with what they're about,
/// their outcomes and no secrets; and shipped into the internal bucket, then
/// deleted once they're past their retention.
#[tokio::test]
async fn calls_are_audited() {
    use crate::audit::{self, log::Rotation, ship};
    use std::time::{Duration, SystemTime};

    let Some(app) = kms_node().await else { return };
    let mut app = Arc::into_inner(app).expect("a new node isn't shared");
    let dir = std::env::temp_dir().join(format!("cairn-audit-{}", uuid::Uuid::new_v4()));
    let rotation = Rotation {
        age: Duration::from_millis(1),
        bytes: u64::MAX,
    };
    app.audit = audit::Audit::start_with(dir.clone(), rotation).unwrap();
    let app = Arc::new(app);
    let admin = admin(&app).await;
    let bob = user(&app, "bob", "").await;

    let made = ok(call_audited(&app, &admin, "CreateKey", json!({ "Description": "d" })).await);
    let arn = made["KeyMetadata"]["Arn"].as_str().unwrap().to_owned();
    let encrypt = json!({
        "KeyId": arn,
        "Plaintext": b64(b"secret"),
        "EncryptionContext": { "Project": "x" },
    });
    let encrypted = ok(call_audited(&app, &admin, "Encrypt", encrypt.clone()).await);
    let blob = encrypted["CiphertextBlob"].as_str().unwrap().to_owned();
    refused(
        call_audited(
            &app,
            &bob,
            "Decrypt",
            json!({ "CiphertextBlob": blob, "EncryptionContext": { "Project": "x" } }),
        )
        .await,
        "AccessDeniedException",
    );

    // Every record is durable once its call returns: in the files, closed
    // soon after.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut data = Vec::new();
    loop {
        let open = std::fs::read_dir(&dir)
            .unwrap()
            .any(|e| e.unwrap().path().extension().is_some_and(|e| e == "open"));
        if !open {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "files weren't closed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for file in audit::log::Log::closed(&dir).unwrap() {
        data.extend(std::fs::read(file).unwrap());
    }
    let events: Vec<Value> = audit::log::records(&data)
        .map(|r| serde_json::from_slice(r).unwrap())
        .collect();
    let names: Vec<&str> = events
        .iter()
        .map(|e| e["eventName"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["CreateKey", "Encrypt", "Decrypt"]);

    let created = &events[0];
    assert_eq!(created["eventSource"], "kms.amazonaws.com");
    assert_eq!(created["readOnly"], false);
    assert_eq!(created["userIdentity"]["type"], "IAMUser");
    assert_eq!(created["userIdentity"]["userName"], "kms-admin");
    assert_eq!(created["userIdentity"]["accessKeyId"], "AKIATEST");
    assert_eq!(created["requestParameters"]["description"], "d");
    assert_eq!(
        created["responseElements"]["keyMetadata"]["arn"],
        arn.as_str()
    );
    assert_eq!(created["resources"][0]["ARN"], arn.as_str());

    let encrypted = &events[1];
    assert_eq!(encrypted["readOnly"], true);
    assert_eq!(encrypted["responseElements"], Value::Null);
    assert_eq!(
        encrypted["requestParameters"],
        json!({ "keyId": arn, "encryptionContext": { "Project": "x" } })
    );
    assert_eq!(encrypted["resources"][0]["ARN"], arn.as_str());
    assert!(!data.windows(8).any(|w| w == b64(b"secret").as_bytes()));

    let denied = &events[2];
    assert_eq!(denied["errorCode"], "AccessDeniedException");
    assert_eq!(denied["userIdentity"]["userName"], "bob");
    assert_eq!(denied["resources"][0]["ARN"], arn.as_str());
    assert!(denied["requestParameters"].get("ciphertextBlob").is_none());

    // An old file, as if it had waited: shipped, then expired.
    let old = dir.join("1600000000000-1-00000000.closed");
    std::fs::write(&old, audit::log::line(r#"{"eventID":"old"}"#)).unwrap();
    let shipped = ship::ship_all(&app, &dir).await.unwrap();
    assert!(shipped >= 2, "{shipped}");
    assert!(audit::log::Log::closed(&dir).unwrap().is_empty());
    let keys = |app: Arc<App>| async move {
        let rows = app
            .pool
            .get()
            .await
            .unwrap()
            .query(
                "SELECT key FROM objects WHERE bucket = $1 AND key LIKE 'audit/%' AND is_latest ORDER BY key",
                &[&crate::internal::BUCKET],
            )
            .await
            .unwrap();
        rows.iter().map(|r| r.get(0)).collect::<Vec<String>>()
    };
    let shipped_keys = keys(app.clone()).await;
    assert_eq!(shipped_keys.len(), shipped);
    assert!(shipped_keys[0].starts_with("audit/2020/09/13/12/1600000000000-1-00000000-"));

    // What's shipped reads back as it was logged.
    let mut shipped_data = Vec::new();
    for key in &shipped_keys[1..] {
        let response = crate::s3::objects::get::get_object(
            &app,
            crate::internal::BUCKET,
            key,
            None,
            None,
            None,
            &Default::default(),
            None,
            None,
            false,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        use http_body_util::BodyExt;
        let gz = response.into_body().collect().await.unwrap().to_bytes();
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut plain).unwrap();
        shipped_data.extend(plain);
    }
    assert_eq!(shipped_data, data);

    ship::expire(&app, SystemTime::now()).await.unwrap();
    assert_eq!(keys(app.clone()).await, shipped_keys[1..]);
    let _ = std::fs::remove_dir_all(&dir);
}
