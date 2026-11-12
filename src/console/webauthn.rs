//! WebAuthn (passkeys), as a relying party: checking what a browser sends
//! back from `navigator.credentials.create()` (a registration) and `.get()`
//! (an assertion), per the W3C's Web Authentication Level 3, §7.1 and §7.2.
//!
//! Cairn doesn't care which authenticator a passkey is on, so it asks for no
//! attestation and ignores any statement it gets: what binds a registration
//! to its user is the enrollment link or session it came through, not a
//! vendor's certificate. Every ceremony requires user verification (a
//! passkey is the only factor), and a credential's public key is one of
//! EdDSA (Ed25519), ES256 (P-256) or RS256, the three every authenticator
//! offers one of. Signatures are checked with `ring`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{digest, signature};

use super::cbor::{self, Value};

/// The COSE algorithms Cairn takes, in the order it prefers them.
pub const ALGORITHMS: [i64; 3] = [EDDSA, ES256, RS256];
const EDDSA: i64 = -8;
const ES256: i64 = -7;
const RS256: i64 = -257;

/// The authenticator data's flags.
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED: u8 = 0x40;
const EXTENSIONS: u8 = 0x80;

/// The most bytes a credential ID may have (§5.1, "credential ID").
const MAX_CREDENTIAL_ID: usize = 1023;

/// Who Cairn is to authenticators: its RP ID (the console URL's host, which
/// credentials are scoped to) and the origin pages must have.
#[derive(Clone, Debug)]
pub struct Party {
    pub id: String,
    pub origin: String,
}

/// Why a ceremony's response is refused, for the person to read.
#[derive(Debug, PartialEq)]
pub struct Refused(pub String);

fn refused<T>(message: impl Into<String>) -> Result<T, Refused> {
    Err(Refused(message.into()))
}

/// A credential a registration made.
#[derive(Debug)]
pub struct NewCredential {
    pub id: Vec<u8>,
    /// Its public key, as the authenticator encoded it (COSE).
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backed_up: bool,
}

/// What an assertion said about its credential.
#[derive(Debug, PartialEq)]
pub struct Asserted {
    pub sign_count: u32,
    pub backed_up: bool,
}

/// Checks a registration's response (§7.1) against the challenge Cairn
/// issued for it, and returns the credential it made.
pub fn verify_registration(
    party: &Party,
    challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<NewCredential, Refused> {
    check_client_data(party, challenge, client_data_json, "webauthn.create")?;
    let attestation = cbor::decode(attestation_object).or_else(|e| refused(format!("attestation object: {}", e.0)))?;
    if attestation.get_text("fmt").and_then(Value::as_text).is_none() {
        return refused("the attestation object has no format");
    }
    let Some(auth_data) = attestation.get_text("authData").and_then(Value::as_bytes) else {
        return refused("the attestation object has no authenticator data");
    };
    let data = AuthData::parse(auth_data)?;
    data.check(party)?;
    let Some((id, public_key)) = data.credential else {
        return refused("the authenticator made no credential");
    };
    // Usable at all: one of ours, and well-formed.
    PublicKey::parse(&public_key)?;
    Ok(NewCredential {
        id,
        public_key,
        sign_count: data.sign_count,
        backup_eligible: data.flags & BACKUP_ELIGIBLE != 0,
        backed_up: data.flags & BACKED_UP != 0,
    })
}

/// Checks an assertion (§7.2) by the credential whose public key is
/// `public_key` against the challenge Cairn issued for it. Whether its
/// signature counter went forward is the caller's to check (it must, for a
/// nonzero one, to detect a cloned authenticator).
pub fn verify_assertion(
    party: &Party,
    challenge: &[u8],
    public_key: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<Asserted, Refused> {
    check_client_data(party, challenge, client_data_json, "webauthn.get")?;
    let data = AuthData::parse(authenticator_data)?;
    data.check(party)?;
    let hash = digest::digest(&digest::SHA256, client_data_json);
    let signed = [authenticator_data, hash.as_ref()].concat();
    PublicKey::parse(public_key)?.verify(&signed, signature)?;
    Ok(Asserted { sign_count: data.sign_count, backed_up: data.flags & BACKED_UP != 0 })
}

/// The client data (§5.8.1): what the browser says the ceremony was, for
/// which challenge, from which page.
fn check_client_data(party: &Party, challenge: &[u8], json: &[u8], kind: &str) -> Result<(), Refused> {
    let Ok(data) = serde_json::from_slice::<serde_json::Value>(json) else {
        return refused("the client data isn't JSON");
    };
    if data["type"].as_str() != Some(kind) {
        return refused(format!("the client data isn't of a {kind}"));
    }
    let sent = data["challenge"].as_str().and_then(|c| URL_SAFE_NO_PAD.decode(c).ok());
    if sent.as_deref() != Some(challenge) {
        return refused("the response is to another challenge");
    }
    if data["origin"].as_str() != Some(party.origin.as_str()) {
        return refused(format!("the response comes from another origin than {}", party.origin));
    }
    if data["crossOrigin"].as_bool() == Some(true) {
        return refused("the response comes from a frame of another origin");
    }
    Ok(())
}

/// Authenticator data (§6.1).
struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    /// The credential a registration made: its ID and COSE public key.
    credential: Option<(Vec<u8>, Vec<u8>)>,
}

impl AuthData {
    fn parse(bytes: &[u8]) -> Result<AuthData, Refused> {
        if bytes.len() < 37 {
            return refused("the authenticator data is too short");
        }
        let rp_id_hash: [u8; 32] = bytes[..32].try_into().unwrap();
        let flags = bytes[32];
        let sign_count = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
        let mut rest = &bytes[37..];
        let mut credential = None;
        if flags & ATTESTED != 0 {
            // AAGUID (16), the ID's length (2), the ID, the key.
            if rest.len() < 18 {
                return refused("the attested credential data is too short");
            }
            let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
            rest = &rest[18..];
            if len == 0 || len > MAX_CREDENTIAL_ID || rest.len() < len {
                return refused("the credential ID's length is invalid");
            }
            let id = rest[..len].to_vec();
            rest = &rest[len..];
            let (_, used) = cbor::decode_prefix(rest).or_else(|e| refused(format!("credential public key: {}", e.0)))?;
            credential = Some((id, rest[..used].to_vec()));
            rest = &rest[used..];
        }
        if flags & EXTENSIONS != 0 {
            // Validated as CBOR, and otherwise ignored: Cairn asks for none.
            cbor::decode(rest).or_else(|e| refused(format!("authenticator extensions: {}", e.0)))?;
        } else if !rest.is_empty() {
            return refused("trailing bytes in the authenticator data");
        }
        Ok(AuthData { rp_id_hash, flags, sign_count, credential })
    }

    /// For this RP, with the user present and verified, and backup flags
    /// that make sense.
    fn check(&self, party: &Party) -> Result<(), Refused> {
        if self.rp_id_hash != digest::digest(&digest::SHA256, party.id.as_bytes()).as_ref() {
            return refused(format!("the credential is for another site than {}", party.id));
        }
        if self.flags & USER_PRESENT == 0 {
            return refused("the authenticator didn't check that the user is present");
        }
        if self.flags & USER_VERIFIED == 0 {
            return refused("the authenticator didn't verify the user (with a PIN or biometrics)");
        }
        if self.flags & BACKED_UP != 0 && self.flags & BACKUP_ELIGIBLE == 0 {
            return refused("the authenticator says a credential that can't be backed up is");
        }
        Ok(())
    }
}

/// A credential's public key (COSE, RFC 9053), of an algorithm Cairn takes.
enum PublicKey {
    Ed25519(Vec<u8>),
    /// The uncompressed point: 0x04, x, y.
    P256(Vec<u8>),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl PublicKey {
    fn parse(cose: &[u8]) -> Result<PublicKey, Refused> {
        let key = cbor::decode(cose).or_else(|e| refused(format!("credential public key: {}", e.0)))?;
        let int = |label| key.get_int(label).and_then(Value::as_int);
        let bytes = |label| key.get_int(label).and_then(Value::as_bytes);
        // kty (1) and alg (3) must go together.
        match (int(1), int(3).map(|a| a as i64)) {
            (Some(1), Some(EDDSA)) => match (int(-1), bytes(-2)) {
                (Some(6), Some(x)) if x.len() == 32 => Ok(PublicKey::Ed25519(x.to_vec())),
                _ => refused("the Ed25519 key is malformed"),
            },
            (Some(2), Some(ES256)) => match (int(-1), bytes(-2), bytes(-3)) {
                (Some(1), Some(x), Some(y)) if x.len() == 32 && y.len() == 32 => {
                    Ok(PublicKey::P256([&[4u8][..], x, y].concat()))
                }
                _ => refused("the P-256 key is malformed"),
            },
            (Some(3), Some(RS256)) => match (bytes(-1), bytes(-2)) {
                // 2048 to 8192 bits, which is what `ring` checks against.
                (Some(n), Some(e)) if (256..=1024).contains(&n.len()) && !e.is_empty() && e.len() <= 8 => {
                    Ok(PublicKey::Rsa { n: n.to_vec(), e: e.to_vec() })
                }
                _ => refused("the RSA key is malformed, or not 2048 to 8192 bits"),
            },
            _ => refused("the credential's key is of an algorithm Cairn doesn't take (EdDSA, ES256, RS256)"),
        }
    }

    fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), Refused> {
        let ok = match self {
            PublicKey::Ed25519(key) => signature::UnparsedPublicKey::new(&signature::ED25519, key).verify(message, sig),
            PublicKey::P256(key) => {
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key).verify(message, sig)
            }
            PublicKey::Rsa { n, e } => signature::RsaPublicKeyComponents { n, e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                sig,
            ),
        };
        ok.or_else(|_| refused("the signature doesn't verify"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    use super::*;
    use crate::console::cbor::tests::encode;

    pub fn party() -> Party {
        Party { id: "console.example.com".into(), origin: "https://console.example.com".into() }
    }

    /// A software authenticator, for tests: an Ed25519 or P-256 key, and a
    /// signature counter.
    pub struct Authenticator {
        pub credential_id: Vec<u8>,
        key: Key,
        pub counter: u32,
        pub flags: u8,
        pub rp_id: String,
        pub origin: String,
    }

    enum Key {
        Ed25519(Ed25519KeyPair),
        P256(EcdsaKeyPair),
    }

    impl Authenticator {
        pub fn ed25519() -> Authenticator {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Authenticator::with(Key::Ed25519(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()))
        }

        pub fn p256() -> Authenticator {
            let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            Authenticator::with(Key::P256(EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).unwrap()))
        }

        fn with(key: Key) -> Authenticator {
            let mut credential_id = vec![0u8; 16];
            getrandom::fill(&mut credential_id).unwrap();
            let party = party();
            Authenticator {
                credential_id,
                key,
                counter: 0,
                flags: USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP,
                rp_id: party.id,
                origin: party.origin,
            }
        }

        fn cose_key(&self) -> Vec<u8> {
            let int = Value::Int;
            encode(&match &self.key {
                Key::Ed25519(k) => Value::Map(vec![
                    (int(1), int(1)),
                    (int(3), int(-8)),
                    (int(-1), int(6)),
                    (int(-2), Value::Bytes(k.public_key().as_ref().to_vec())),
                ]),
                Key::P256(k) => {
                    let point = k.public_key().as_ref();
                    Value::Map(vec![
                        (int(1), int(2)),
                        (int(3), int(-7)),
                        (int(-1), int(1)),
                        (int(-2), Value::Bytes(point[1..33].to_vec())),
                        (int(-3), Value::Bytes(point[33..].to_vec())),
                    ])
                }
            })
        }

        fn auth_data(&self, attested: bool) -> Vec<u8> {
            let mut data = digest::digest(&digest::SHA256, self.rp_id.as_bytes()).as_ref().to_vec();
            data.push(self.flags | if attested { ATTESTED } else { 0 });
            data.extend(self.counter.to_be_bytes());
            if attested {
                data.extend([0u8; 16]);
                data.extend((self.credential_id.len() as u16).to_be_bytes());
                data.extend(&self.credential_id);
                data.extend(self.cose_key());
            }
            data
        }

        pub fn client_data(&self, kind: &str, challenge: &[u8]) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "type": kind,
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": self.origin,
                "crossOrigin": false,
            }))
            .unwrap()
        }

        /// `navigator.credentials.create()`'s response: client data JSON and
        /// attestation object.
        pub fn register(&mut self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let attestation = encode(&Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text("none".into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (Value::Text("authData".into()), Value::Bytes(self.auth_data(true))),
            ]));
            (self.client_data("webauthn.create", challenge), attestation)
        }

        /// `navigator.credentials.get()`'s response: client data JSON,
        /// authenticator data, signature. Counts up first, if it counts.
        pub fn assert(&mut self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            if self.counter > 0 {
                self.counter += 1;
            }
            let client_data = self.client_data("webauthn.get", challenge);
            let auth_data = self.auth_data(false);
            let hash = digest::digest(&digest::SHA256, &client_data);
            let signed = [&auth_data[..], hash.as_ref()].concat();
            let sig = match &self.key {
                Key::Ed25519(k) => k.sign(&signed).as_ref().to_vec(),
                Key::P256(k) => k.sign(&SystemRandom::new(), &signed).unwrap().as_ref().to_vec(),
            };
            (client_data, auth_data, sig)
        }
    }

    #[test]
    fn registers_and_asserts_with_either_key() {
        for mut authenticator in [Authenticator::ed25519(), Authenticator::p256()] {
            authenticator.counter = 5;
            let (client_data, attestation) = authenticator.register(b"challenge-1");
            let credential = verify_registration(&party(), b"challenge-1", &client_data, &attestation).unwrap();
            assert_eq!(credential.id, authenticator.credential_id);
            assert_eq!(credential.sign_count, 5);
            assert!(credential.backup_eligible && credential.backed_up);

            let (client_data, auth_data, sig) = authenticator.assert(b"challenge-2");
            let asserted =
                verify_assertion(&party(), b"challenge-2", &credential.public_key, &client_data, &auth_data, &sig)
                    .unwrap();
            assert_eq!(asserted, Asserted { sign_count: 6, backed_up: true });

            // Not for another challenge, nor with another signature.
            let err = verify_assertion(&party(), b"other", &credential.public_key, &client_data, &auth_data, &sig);
            assert_eq!(err.unwrap_err().0, "the response is to another challenge");
            let mut bad = sig.clone();
            *bad.last_mut().unwrap() ^= 1;
            let err = verify_assertion(&party(), b"challenge-2", &credential.public_key, &client_data, &auth_data, &bad);
            assert_eq!(err.unwrap_err().0, "the signature doesn't verify");
            // Nor with authenticator data changed after signing.
            let mut changed = auth_data.clone();
            changed[33] ^= 1;
            let err = verify_assertion(&party(), b"challenge-2", &credential.public_key, &client_data, &changed, &sig);
            assert_eq!(err.unwrap_err().0, "the signature doesn't verify");
        }
    }

    #[test]
    fn refuses_other_sites_ceremonies_and_unverified_users() {
        let check = |change: &dyn Fn(&mut Authenticator)| {
            let mut authenticator = Authenticator::ed25519();
            change(&mut authenticator);
            let (client_data, attestation) = authenticator.register(b"c");
            verify_registration(&party(), b"c", &client_data, &attestation).unwrap_err().0
        };
        assert_eq!(check(&|a| a.origin = "https://evil.example.com".into()),
            "the response comes from another origin than https://console.example.com");
        assert_eq!(check(&|a| a.rp_id = "example.com".into()), "the credential is for another site than console.example.com");
        assert_eq!(check(&|a| a.flags &= !USER_VERIFIED), "the authenticator didn't verify the user (with a PIN or biometrics)");
        assert_eq!(check(&|a| a.flags &= !USER_PRESENT), "the authenticator didn't check that the user is present");
        assert_eq!(check(&|a| a.flags &= !BACKUP_ELIGIBLE), "the authenticator says a credential that can't be backed up is");

        // An assertion's client data is not a registration's.
        let mut authenticator = Authenticator::ed25519();
        let (_, attestation) = authenticator.register(b"c");
        let client_data = authenticator.client_data("webauthn.get", b"c");
        let err = verify_registration(&party(), b"c", &client_data, &attestation).unwrap_err();
        assert_eq!(err.0, "the client data isn't of a webauthn.create");
    }

    #[test]
    fn refuses_malformed_responses() {
        let mut authenticator = Authenticator::ed25519();
        let (client_data, attestation) = authenticator.register(b"c");
        // Truncated anywhere.
        for len in 0..attestation.len() {
            assert!(verify_registration(&party(), b"c", &client_data, &attestation[..len]).is_err(), "{len}");
        }
        // Trailing bytes in the authenticator data.
        let auth_data = [authenticator.auth_data(true), vec![0]].concat();
        let attestation = encode(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (Value::Text("authData".into()), Value::Bytes(auth_data)),
        ]));
        let err = verify_registration(&party(), b"c", &client_data, &attestation).unwrap_err();
        assert_eq!(err.0, "trailing bytes in the authenticator data");
        // A key of an algorithm Cairn doesn't take (ES384).
        let cose = encode(&Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(-35))]));
        assert!(PublicKey::parse(&cose).is_err());
        // A kty that doesn't match its alg.
        let cose = encode(&Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(-8))]));
        assert!(PublicKey::parse(&cose).is_err());
    }
}
