use crate::crypto::random_bytes;
use hmac::{Hmac, Mac};
use sha1::Sha1;

const DEFAULT_DIGITS: u32 = 6;
const DEFAULT_STEP: u64 = 30;

pub fn generate_totp_secret() -> Vec<u8> {
    random_bytes(20)
}

pub fn totp_code(secret: &[u8], time: u64, digits: u32, step: u64) -> String {
    let counter = time / step;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac key");
    mac.update(&counter_bytes);
    let mac_bytes = mac.finalize().into_bytes();

    let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0f) as usize;
    let bin = ((mac_bytes[offset] & 0x7f) as u32) << 24
        | (mac_bytes[offset + 1] as u32) << 16
        | (mac_bytes[offset + 2] as u32) << 8
        | (mac_bytes[offset + 3] as u32);

    let code = bin % 10u32.pow(digits);
    format!("{:0width$}", code, width = digits as usize)
}

pub fn totp_now(secret: &[u8]) -> String {
    let time = chrono::Utc::now().timestamp() as u64;
    totp_code(secret, time, DEFAULT_DIGITS, DEFAULT_STEP)
}

pub fn is_totp_code_valid(input: &str, secret: &[u8]) -> bool {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() != DEFAULT_DIGITS as usize || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let now = chrono::Utc::now().timestamp();
    for offset in [-30i64, 0, 30] {
        let t = (now + offset) as u64;
        let code = totp_code(secret, t, DEFAULT_DIGITS, DEFAULT_STEP);
        if constant_time_str_eq(&code, &cleaned) {
            return true;
        }
    }
    false
}

fn constant_time_str_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn to_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = String::new();
    for &b in bytes {
        value = (value << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((value >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((value << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn otpauth_uri(secret: &[u8], label: &str, issuer: &str) -> String {
    let secret_b32 = to_base32(secret);
    let label_enc = urlencode(label);
    let issuer_enc = urlencode(issuer);
    format!(
        "otpauth://totp/{issuer}:{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        issuer = issuer_enc,
        label = label_enc,
        secret = secret_b32,
    )
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            for b in c.to_string().as_bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_known_vector() {
        // RFC 6238 Appendix B test vector: key="12345678901234567890" t=59 → 94287082 (8 digits)
        let key = b"12345678901234567890";
        let code = totp_code(key, 59, 8, 30);
        assert_eq!(code, "94287082");
    }

    #[test]
    fn totp_changes_with_time() {
        let secret = generate_totp_secret();
        let c1 = totp_code(&secret, 1000, 6, 30);
        let c2 = totp_code(&secret, 1030, 6, 30);
        assert_ne!(c1, c2);
    }

    #[test]
    fn validity_window() {
        let secret = generate_totp_secret();
        let code = totp_now(&secret);
        assert!(is_totp_code_valid(&code, &secret));
        assert!(!is_totp_code_valid("000000", &secret));
        assert!(!is_totp_code_valid("abc123", &secret));
    }

    #[test]
    fn base32_known_vectors() {
        assert_eq!(to_base32(b""), "");
        assert_eq!(to_base32(b"f"), "MY");
        assert_eq!(to_base32(b"foo"), "MZXW6");
    }
}
