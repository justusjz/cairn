//! MFA delete (see `s3::buckets::versioning`): the account's root user's
//! virtual MFA device, and the codes of it that requests carry in
//! `x-amz-mfa`, as AWS's.
//!
//! A bucket with MFA delete enabled takes no request that deletes a version
//! for good or changes its versioning (MFA delete included) without the
//! root's code; and only the root's own request may give one (AWS's docs:
//! "only the root user can permanently delete object versions or change the
//! versioning configuration"). The root has no device until `cairn account
//! root-mfa` makes one on a node, so a cluster that never makes one never
//! has MFA delete. The device is a second factor, not a way in: being the
//! root still takes a node (see `accounts`).
//!
//! Codes are RFC 6238's TOTP, as authenticator apps make them: HMAC-SHA1,
//! six digits, 30-second steps, taken from the step before to the step
//! after now. A code may be used more than once while it lasts, so that a
//! script may delete many versions with one. The device's secret is kept as
//! it is, as access keys' secrets are: it's checked, not just compared.

use deadpool_postgres::Object;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::Full;
use hyper::{HeaderMap, Response, StatusCode, body::Bytes};
use sha1::Sha1;

use crate::db::Cached;
use crate::{App, s3::util::format_s3_error, users::Principal};

/// The header the root's code comes in: its device's serial number, a space
/// and the code.
pub const HEADER: &str = "x-amz-mfa";

/// The root's virtual MFA device's name, in its serial number (its ARN), as
/// AWS names a root's.
const DEVICE: &str = "root-account-mfa-device";

/// A code's step, in seconds.
const STEP: u64 = 30;

/// How many digits a code has.
const DIGITS: usize = 6;

/// The length of a device's secret: SHA-1's, as RFC 4226 recommends.
const SECRET_LEN: usize = 20;

/// The serial number of the root's device: its ARN.
pub fn serial(account: &str) -> String {
    format!("arn:aws:iam::{account}:mfa/{DEVICE}")
}

/// RFC 4226's HOTP: the code for counter `counter`.
fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key");
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let truncated = u32::from_be_bytes([
        hash[offset],
        hash[offset + 1],
        hash[offset + 2],
        hash[offset + 3],
    ]) & 0x7fff_ffff;
    truncated % 10u32.pow(DIGITS as u32)
}

/// RFC 6238's TOTP: the code for step `step`, as its six digits.
fn code_of_step(secret: &[u8], step: u64) -> String {
    format!("{:0width$}", hotp(secret, step), width = DIGITS)
}

/// The code for the step that `unix` (seconds) is in, as an authenticator
/// app shows it then.
#[cfg(test)]
pub fn code(secret: &[u8], unix: u64) -> String {
    code_of_step(secret, unix / STEP)
}

/// Whether `given` is a code of `secret`'s at `unix`: of its step, or the
/// one before or after (a clock that's a little off, a code typed as its
/// step ends).
fn verify(secret: &[u8], given: &str, unix: u64) -> bool {
    if given.len() != DIGITS || !given.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = unix / STEP;
    // Every candidate compared in full, whichever matches.
    [step.saturating_sub(1), step, step + 1]
        .iter()
        .fold(false, |matched, &counter| {
            let expected = code_of_step(secret, counter);
            let differs = expected
                .bytes()
                .zip(given.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b));
            matched | (differs == 0)
        })
}

/// RFC 4648's base32, without padding: how authenticator apps take a secret.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The `otpauth://` URI an authenticator app takes the device from (as a
/// QR code, or pasted).
pub fn uri(account: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/Cairn:root%40{account}?secret={}&issuer=Cairn&algorithm=SHA1&digits={DIGITS}&period={STEP}",
        base32(secret)
    )
}

/// Makes the root's device, replacing the one it had (if `replace`; else
/// none is made if it has one). Its secret, if it was made.
pub async fn make_device(
    client: &Object,
    account: &str,
    replace: bool,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut secret = vec![0u8; SECRET_LEN];
    getrandom::fill(&mut secret).expect("the OS random number generator failed");
    let made = client
        .execute(
            &format!(
                "INSERT INTO root_mfa_devices (account_id, secret) VALUES ($1, $2)
                 ON CONFLICT (account_id) DO {}",
                if replace {
                    "UPDATE SET secret = EXCLUDED.secret, created_at = now()"
                } else {
                    "NOTHING"
                }
            ),
            &[&account, &secret],
        )
        .await?;
    Ok((made == 1).then_some(secret))
}

/// The secret of the root's device, if it has one.
async fn secret_of(client: &Object, account: &str) -> anyhow::Result<Option<Vec<u8>>> {
    Ok(client
        .query_opt_cached(
            "SELECT secret FROM root_mfa_devices WHERE account_id = $1",
            &[&account],
        )
        .await?
        .map(|row| row.get(0)))
}

/// What a request's `x-amz-mfa` came to: a code of the root's device, given
/// by the root (`Valid`); something else (`Invalid`); or nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented {
    Absent,
    Valid,
    Invalid,
}

impl Presented {
    /// As the catalog's functions take it: NULL for none, else whether it's
    /// valid.
    pub fn as_db(self) -> Option<bool> {
        match self {
            Presented::Absent => None,
            Presented::Valid => Some(true),
            Presented::Invalid => Some(false),
        }
    }
}

/// The serial number and code an `x-amz-mfa` holds: two words, as AWS's
/// clients send them, or percent-encoded (as AWS's docs say signed headers
/// with spaces are).
fn parse(value: &str) -> Option<(String, String)> {
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .ok()?;
    let mut words = decoded.split_ascii_whitespace();
    let (serial, code) = (words.next()?, words.next()?);
    words
        .next()
        .is_none()
        .then(|| (serial.to_owned(), code.to_owned()))
}

/// What the request's `x-amz-mfa` came to, for `principal`: a refusal if it
/// came over plain HTTP, as AWS's docs say "Requests that include x-amz-mfa
/// must use HTTPS" (which the proxy in front of Cairn tells; see
/// `s3::sse_c::secure`). A code is valid only from the root, of its own
/// device, by its serial number.
pub async fn presented(
    app: &App,
    principal: Option<&Principal>,
    headers: &HeaderMap,
) -> anyhow::Result<Result<Presented, Response<Full<Bytes>>>> {
    let Some(value) = headers.get(HEADER) else {
        return Ok(Ok(Presented::Absent));
    };
    if !crate::s3::sse_c::secure(headers, false) {
        return Ok(Err(format_s3_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "Requests that include x-amz-mfa must use HTTPS.",
        )));
    }
    let Some((serial_number, given)) = value.to_str().ok().and_then(parse) else {
        return Ok(Ok(Presented::Invalid));
    };
    let Some(root) = principal.filter(|p| p.root) else {
        return Ok(Ok(Presented::Invalid));
    };
    if serial_number != serial(&root.account) {
        return Ok(Ok(Presented::Invalid));
    }
    let Some(secret) = secret_of(&app.pool.get().await?, &root.account).await? else {
        return Ok(Ok(Presented::Invalid));
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok(Ok(match verify(&secret, &given, now) {
        true => Presented::Valid,
        false => Presented::Invalid,
    }))
}

/// The refusal of a request that MFA delete wants the root's code for, and
/// that didn't give a valid one.
pub fn required() -> Response<Full<Bytes>> {
    format_s3_error(
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "Mfa Authentication must be used for this request",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA-1 test vectors (appendix B), as six digits: the last
    /// six of its eight.
    #[test]
    fn codes_are_rfc_6238s() {
        let secret = b"12345678901234567890";
        for (unix, eight) in [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            assert_eq!(code(secret, unix), eight[2..], "at {unix}");
        }
    }

    #[test]
    fn a_code_lasts_its_step_and_its_neighbours() {
        let secret = b"12345678901234567890";
        let now = 1111111111;
        let current = code(secret, now);
        assert!(verify(secret, &current, now));
        assert!(verify(secret, &current, now + STEP));
        assert!(verify(secret, &current, now - STEP));
        assert!(!verify(secret, &current, now + 2 * STEP));
        assert!(!verify(secret, &current, now - 2 * STEP));
        assert!(!verify(secret, "", now));
        assert!(!verify(secret, &format!("{current}0"), now));
        assert!(!verify(secret, "abcdef", now));
    }

    #[test]
    fn base32_is_rfc_4648s() {
        // RFC 4648's test vectors, without their padding.
        for (plain, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(plain.as_bytes()), encoded);
        }
    }

    #[test]
    fn the_header_is_a_serial_number_and_a_code() {
        let serial = "arn:aws:iam::123456789012:mfa/root-account-mfa-device";
        let parsed = Some((serial.to_owned(), "123456".to_owned()));
        assert_eq!(parse(&format!("{serial} 123456")), parsed);
        assert_eq!(parse(&format!("{serial}%20123456")), parsed);
        assert_eq!(parse(&format!("  {serial}  123456 ")), parsed);
        assert_eq!(parse(serial), None);
        assert_eq!(parse(&format!("{serial} 123456 7")), None);
    }
}
