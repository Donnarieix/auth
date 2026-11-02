//! RFC 6238 TOTP with HMAC-SHA256 (30-second interval, 6 digits).
//! Only used for developer administrators; secrets must never be logged.
use sha2::{Digest, Sha256};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn encode_base32(bytes: &[u8]) -> String {
    let mut value = 0u32;
    let mut bits = 0;
    let mut result = String::new();
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(ALPHABET[((value >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        result.push(char::from(ALPHABET[((value << (5 - bits)) & 31) as usize]));
    }
    result
}

pub fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 64];
    if secret.len() > 64 {
        key[..32].copy_from_slice(&Sha256::digest(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= key[i];
        outer[i] ^= key[i];
    }
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(inner);
    inner_hasher.update(message);
    let inner_digest = inner_hasher.finalize();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(outer);
    outer_hasher.update(inner_digest);
    outer_hasher.finalize().into()
}

pub fn code(secret: &[u8], step: u64) -> u32 {
    let hash = hmac_sha256(secret, &step.to_be_bytes());
    let offset = usize::from(hash[31] & 15);
    let truncated = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    truncated % 1_000_000
}

// SHA1 is supported for authenticator interoperability. SHA256 remains
// supported for already-enrolled administrators, with the selected algorithm
// recorded in the database: never auto-fallback between algorithms.
pub fn code_sha1(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let offset = usize::from(bytes[19] & 0x0f);
    let truncated = (u32::from(bytes[offset] & 0x7f) << 24)
        | (u32::from(bytes[offset + 1]) << 16)
        | (u32::from(bytes[offset + 2]) << 8)
        | u32::from(bytes[offset + 3]);
    truncated % 1_000_000
}

/// Returns the matched step; the DB consumes it atomically to prevent replay.
pub fn verify_algorithm(
    secret: &[u8],
    supplied: &str,
    unix_seconds: i64,
    last_step: i64,
    algorithm: &str,
) -> Option<i64> {
    if secret.len() != 32 || supplied.len() != 6 || !supplied.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let supplied: u32 = supplied.parse().ok()?;
    let calculate: fn(&[u8], u64) -> u32 = match algorithm {
        "SHA1" => code_sha1,
        "SHA256" => code,
        _ => return None,
    };
    let current = unix_seconds.checked_div(30)?;
    [current - 1, current, current + 1]
        .into_iter()
        .find(|&step| step >= 0 && step > last_step && calculate(secret, step as u64) == supplied)
}

#[cfg(test)]
pub fn verify(secret: &[u8], supplied: &str, unix_seconds: i64, last_step: i64) -> Option<i64> {
    verify_algorithm(secret, supplied, unix_seconds, last_step, "SHA256")
}

#[cfg(test)]
mod tests {
    use super::{code, code_sha1, encode_base32, hmac_sha256, verify, verify_algorithm};

    #[test]
    fn sha1_is_interoperable_and_legacy_sha256_does_not_fallback() {
        let secret = b"12345678901234567890";
        // RFC 6238 8-digit HOTP-SHA1 vector at 59 seconds is 94287082.
        assert_eq!(code_sha1(secret, 59 / 30), 287082);
        let key = b"12345678901234567890123456789012";
        let now = 1_800_000_000_i64;
        let step = (now / 30) as u64;
        let sha1 = format!("{:06}", code_sha1(key, step));
        assert_eq!(verify_algorithm(key, &sha1, now, -1, "SHA1"), Some(step as i64));
        assert_eq!(verify_algorithm(key, &sha1, now, step as i64, "SHA1"), None);
        assert_eq!(verify_algorithm(key, &sha1, now, -1, "INVALID"), None);
        let sha256 = format!("{:06}", code(key, step));
        assert_eq!(verify_algorithm(key, &sha256, now, -1, "SHA256"), Some(step as i64));
    }

    #[test]
    fn rfc_vectors_and_non_replay() {
        let secret = b"12345678901234567890123456789012";
        assert_eq!(code(secret, 59 / 30), 119246);
        let input = format!("{:06}", code(secret, 1));
        assert_eq!(verify(secret, &input, 59, -1), Some(1));
        assert_eq!(verify(secret, &input, 59, 1), None);
        assert_eq!(verify(secret, "12345X", 59, -1), None);
        assert_eq!(encode_base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(hmac_sha256(b"key", b"data").len(), 32);
    }
}
