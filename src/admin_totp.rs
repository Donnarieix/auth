//! RFC 6238 TOTP with HMAC-SHA256 (30-second interval, 6 digits).
//! Only used for developer administrators; secrets must never be logged.
use sha2::{Digest, Sha256};

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

/// Returns the matched counter, which the database must consume atomically.
pub fn verify(secret: &[u8], supplied: &str, unix_seconds: i64, last_step: i64) -> Option<i64> {
    if secret.len() != 32 || supplied.len() != 6 || !supplied.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let supplied: u32 = supplied.parse().ok()?;
    let current = unix_seconds.checked_div(30)?;
    for step in [current - 1, current, current + 1] {
        if step >= 0 && step > last_step && code(secret, step as u64) == supplied {
            return Some(step);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{code, encode_base32, hmac_sha256, verify};

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
