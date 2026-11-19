//! SNS's message signatures (probed, see `plans/notifications.md`): an RSA
//! PKCS#1 v1.5 signature, over SHA1 (`SignatureVersion` 1, the default) or
//! SHA256 (2), of the message's fields in a fixed order, each as its name and
//! value on lines of their own. Receivers check it with the certificate at
//! the message's `SigningCertURL`, which Cairn serves itself, unsigned
//! (`/SimpleNotificationService-<id>.pem`, a path no bucket's request has:
//! bucket names have no capitals).
//!
//! The keys are the cluster's, in Postgres (`sns_signing_keys`, as
//! `session_keys` are: a database leak exposes users' long-term secrets
//! anyway): 2048-bit, with self-signed certificates. Messages are signed with
//! the newest. The maintenance pass makes a new one every `ROTATE`, and drops
//! those older than that twice over, so a certificate stays served for a
//! while after its last message.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::{
    PrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    signature::{SignatureEncoding, Signer},
};

use crate::db::Cached;

/// How long a key signs messages, before a new one does.
pub const ROTATE: Duration = Duration::from_secs(30 * 24 * 3600);

/// The fields a notification's signature covers, in order.
pub const NOTIFICATION_FIELDS: &[&str] = &[
    "Message",
    "MessageId",
    "Subject",
    "Timestamp",
    "TopicArn",
    "Type",
];
/// Those of a subscription's (or unsubscription's) confirmation.
pub const CONFIRMATION_FIELDS: &[&str] = &[
    "Message",
    "MessageId",
    "SubscribeURL",
    "Timestamp",
    "Token",
    "TopicArn",
    "Type",
];

/// A signing key: its ID (which its certificate's file name has), and the
/// key.
pub struct Key {
    pub id: i32,
    key: PrivateKey,
}

/// The string a message's signature is over: each of `fields` it has
/// (`value` gives them), as `Name\nValue\n`.
pub fn string_to_sign(fields: &[&str], value: impl Fn(&str) -> Option<String>) -> String {
    fields
        .iter()
        .filter_map(|name| value(name).map(|v| format!("{name}\n{v}\n")))
        .collect()
}

impl Key {
    /// `text` signed, as `version` (1: SHA1, 2: SHA256) says, in base64.
    pub fn sign(&self, version: i16, text: &str) -> String {
        let signature = match version {
            2 => SigningKey::<sha2::Sha256>::new(self.key.clone())
                .sign(text.as_bytes())
                .to_bytes(),
            _ => SigningKey::<sha1::Sha1>::new(self.key.clone())
                .sign(text.as_bytes())
                .to_bytes(),
        };
        STANDARD.encode(signature)
    }
}

/// A certificate's file's name.
pub fn certificate_name(id: i32) -> String {
    format!("SimpleNotificationService-{:032x}.pem", id)
}

/// The key ID a certificate's path names, if it's one's.
pub fn certificate_id(path: &str) -> Option<i32> {
    let hex = path
        .strip_prefix("/SimpleNotificationService-")?
        .strip_suffix(".pem")?;
    (hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| i64::from_str_radix(hex, 16).ok())?
        .and_then(|n| i32::try_from(n).ok())
}

/// A new key, and its certificate (PEM), self-signed.
fn generate() -> anyhow::Result<(Vec<u8>, String)> {
    let key = PrivateKey::new(&mut getrandom::SysRng, 2048)?;
    let der = key.to_pkcs8_der()?;
    let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(der.as_bytes().to_vec());
    let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)?;
    let mut params = rcgen::CertificateParams::new(vec!["sns.cairn".to_owned()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "sns.cairn");
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(9999, 12, 31);
    let certificate = params.self_signed(&pair)?;
    Ok((der.as_bytes().to_vec(), certificate.pem()))
}

/// The newest key; one made first, if there's none, or none newer than
/// `ROTATE` (`rotate`).
pub async fn current(client: &deadpool_postgres::Object, rotate: bool) -> anyhow::Result<Key> {
    let interval = format!("{} seconds", ROTATE.as_secs());
    let newest = client
        .query_opt_cached(
            "SELECT id, private_key, created_at > now() - $1::text::interval FROM sns_signing_keys ORDER BY id DESC LIMIT 1",
            &[&interval],
        )
        .await?;
    if let Some(row) = newest
        && (!rotate || row.get::<_, bool>(2))
    {
        let der: Vec<u8> = row.get(1);
        return Ok(Key {
            id: row.get(0),
            key: PrivateKey::from_pkcs8_der(&der)?,
        });
    }
    // Generating takes a while: not on the async runtime's threads.
    let (der, certificate) = tokio::task::spawn_blocking(generate).await??;
    let id: i32 = client
        .query_one_cached(
            "INSERT INTO sns_signing_keys (private_key, certificate) VALUES ($1, $2) RETURNING id",
            &[&der, &certificate],
        )
        .await?
        .get(0);
    // Keys well past signing anything: their certificates' messages are long
    // delivered, or given up.
    let interval = format!("{} seconds", 2 * ROTATE.as_secs());
    client
        .execute_cached(
            "DELETE FROM sns_signing_keys WHERE created_at < now() - $1::text::interval AND id <> $2",
            &[&interval, &id],
        )
        .await?;
    Ok(Key {
        id,
        key: PrivateKey::from_pkcs8_der(&der)?,
    })
}

/// A key's certificate, PEM, if it's still kept.
pub async fn certificate(
    client: &deadpool_postgres::Object,
    id: i32,
) -> anyhow::Result<Option<String>> {
    Ok(client
        .query_opt_cached(
            "SELECT certificate FROM sns_signing_keys WHERE id = $1",
            &[&id],
        )
        .await?
        .map(|r| r.get(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier,
    };

    #[test]
    fn signs_as_sns_does() {
        let (der, pem) = generate().unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        let key = Key {
            id: 7,
            key: PrivateKey::from_pkcs8_der(&der).unwrap(),
        };
        let fields = [
            ("Message", "hello"),
            ("MessageId", "m"),
            ("Timestamp", "t"),
            ("TopicArn", "a"),
            ("Type", "Notification"),
        ];
        let text = string_to_sign(NOTIFICATION_FIELDS, |name| {
            fields
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.to_string())
        });
        assert_eq!(
            text,
            "Message\nhello\nMessageId\nm\nTimestamp\nt\nTopicArn\na\nType\nNotification\n"
        );
        let public = key.key.to_public_key();
        for version in [1, 2] {
            let signature = STANDARD.decode(key.sign(version, &text)).unwrap();
            let signature = Signature::try_from(signature.as_slice()).unwrap();
            match version {
                1 => VerifyingKey::<sha1::Sha1>::new(public.clone())
                    .verify(text.as_bytes(), &signature)
                    .unwrap(),
                _ => VerifyingKey::<sha2::Sha256>::new(public.clone())
                    .verify(text.as_bytes(), &signature)
                    .unwrap(),
            }
        }
        assert_eq!(
            certificate_id(&format!("/{}", certificate_name(7))),
            Some(7)
        );
        assert_eq!(certificate_id("/SimpleNotificationService-zz.pem"), None);
    }
}
