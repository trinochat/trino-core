//! XEdDSA over Curve25519: Ed25519-compatible signatures made with an X25519
//! key (`diseno-vinculacion.md` §3.1, RV-19; decided 30 Oct 2026 to write
//! it here, over `curve25519-dalek`, rather than take a crate).
//!
//! A device list entry carries `dh_sig`, made with the device's X25519 key
//! `dev_dh`, to prove that whoever lists that key holds its private half.
//! Without it, anyone could list someone else's `dev_dh` and take over their
//! introduction mailboxes.
//!
//! The scheme is Signal's, "The XEdDSA and VXEdDSA Signature Schemes",
//! revision 1, 2016-10-20 (<https://signal.org/docs/specifications/xeddsa/>),
//! §2.3, §2.5 and §3.3:
//!
//! ```text
//! calculate_key_pair(k):  E = kB;  A.y = E.y, A.s = 0;  a = -k (mod q) if E.s = 1, else k (mod q)
//! sign(k, M, Z):          r = hash1(a ‖ M ‖ Z) (mod q);  R = rB;  h = hash(R ‖ A ‖ M) (mod q)
//!                         s = r + h·a (mod q);           signature = R ‖ s           (64 bytes)
//! verify(u, M, R ‖ s):    u < p and s < q;  A = convert_mont(u): y = (u − 1)/(u + 1), sign bit 0
//!                         accept iff R = sB − hA
//! ```
//!
//! `hash` is SHA-512 and `hash1(X) = SHA-512(0xFE ‖ 0xFF×31 ‖ X)`. `k` is the
//! X25519 private key after X25519's own clamping, so `E` is the Edwards form
//! of the very key X25519 publishes, and `A` its form with the sign bit 0.
//! A signature is a standard Ed25519 signature under `A`.
//!
//! - **`Z` is 64 random bytes** on every signature. Two signatures of the
//!   same message differ; a weak generator alone cannot leak `a`, because
//!   `r` also hashes `a`.
//! - **Verification is stricter than the specification asks:** `s` must be
//!   below `q` (the specification only bounds it by 2^253), and `A` must
//!   lie in the prime-order subgroup, so a small-order or mixed-order key
//!   never verifies (with a small-order key a signature could be forged
//!   without any secret). An honest key always passes both.
//! - **Not libsignal's variant.** libsignal keeps the Edwards sign bit in the
//!   top bit of `s` instead of fixing it to 0. Its signatures with that bit
//!   set do not verify here, by design; the specification's do.
//! - **Secrets are wiped:** the clamped key, `a`, `−k`, `r` and the hash
//!   outputs live in `Zeroizing` buffers; the choice between `k` and `−k` is
//!   constant time. The SHA-512 state itself is not wiped (the `sha2` crate
//!   offers no way), as in `ed25519-dalek`.
//! - **No `unsafe`.**
//!
//! The tests check vectors made by `tests/vectors/xeddsa.py`, written from
//! the specification, where OpenSSL checks each signature as Ed25519 under
//! `A`; and the `xeddsa_fast_test` vector of libsignal-protocol-c, which this
//! code reproduces byte for byte (`tests/vectors/xeddsa_libsignal.json`).
//!
//! This module is in the scope of the external audit (AUD-2).

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{clamp_integer, Scalar};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha512};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// An XEdDSA signature: `R ‖ s`.
pub const SIGNATURE_LEN: usize = 64;

/// `hash1`'s prefix: 2^256 − 1 − 1, little-endian (specification §2.5).
const HASH1_PREFIX: [u8; 32] = {
    let mut p = [0xFF; 32];
    p[0] = 0xFE;
    p
};

/// The Edwards public key `A` (sign bit 0) and the private scalar `a` of an
/// X25519 private key `k`.
pub fn calculate_key_pair(k: &[u8; 32]) -> ([u8; 32], Zeroizing<Scalar>) {
    let clamped = Zeroizing::new(clamp_integer(*k));
    // k < 2^255 and kB = (k mod q)B, since B has order q.
    let k = Zeroizing::new(Scalar::from_bytes_mod_order(*clamped));
    let e = EdwardsPoint::mul_base(&k).compress();
    let mut a_pub = e.to_bytes();
    let e_sign = Choice::from(a_pub[31] >> 7);
    a_pub[31] &= 0x7F;
    let minus_k = Zeroizing::new(-*k);
    let a = Zeroizing::new(Scalar::conditional_select(&k, &minus_k, e_sign));
    (a_pub, a)
}

/// Signs `msg` with the X25519 private key `k`, with 64 fresh random bytes.
pub fn sign(k: &[u8; 32], msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    sign_with_rng(k, msg, &mut OsRng)
}

/// [`sign`] with the 64 random bytes drawn from `rng`.
pub fn sign_with_rng<R: RngCore + CryptoRng>(
    k: &[u8; 32],
    msg: &[u8],
    rng: &mut R,
) -> [u8; SIGNATURE_LEN] {
    let mut z = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(&mut z[..]);
    sign_with_z(k, msg, &z)
}

/// The signature with a given `Z`, for the vectors.
fn sign_with_z(k: &[u8; 32], msg: &[u8], z: &[u8; 64]) -> [u8; SIGNATURE_LEN] {
    let (a_pub, a) = calculate_key_pair(k);

    let mut hash1 = Sha512::new();
    hash1.update(HASH1_PREFIX);
    hash1.update(a.as_bytes());
    hash1.update(msg);
    hash1.update(z);
    let mut wide = Zeroizing::new([0u8; 64]);
    hash1.finalize_into(GenericArray::from_mut_slice(&mut wide[..]));
    let r = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&wide));

    let big_r = EdwardsPoint::mul_base(&r).compress();
    let h = challenge(big_r.as_bytes(), &a_pub, msg);
    let s = Zeroizing::new(h * *a + *r);

    let mut out = [0u8; SIGNATURE_LEN];
    out[..32].copy_from_slice(big_r.as_bytes());
    out[32..].copy_from_slice(s.as_bytes());
    out
}

/// `hash(R ‖ A ‖ M) (mod q)`.
fn challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut hash = Sha512::new();
    hash.update(r);
    hash.update(a);
    hash.update(msg);
    let mut wide = [0u8; 64];
    hash.finalize_into(GenericArray::from_mut_slice(&mut wide));
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Whether the 32 little-endian bytes are an integer below p = 2^255 − 19.
fn is_canonical_field_element(u: &[u8; 32]) -> bool {
    // Public data: no need for constant time.
    if u[31] & 0x80 != 0 {
        return false;
    }
    // Below 2^255; it is p or more only if every bit from 5 to 254 is set
    // and the low byte is at least 0xED.
    !(u[31] == 0x7F && u[1..31].iter().all(|&b| b == 0xFF) && u[0] >= 0xED)
}

/// `convert_mont` as a point, with the checks that [`convert_mont`] lists.
fn edwards_of(u: &[u8; 32]) -> Option<EdwardsPoint> {
    if !is_canonical_field_element(u) {
        return None;
    }
    // y = (u − 1)/(u + 1) with the sign bit 0; `None` for u = −1 and for a
    // u whose y is not on the curve (a point of the twist).
    let a = MontgomeryPoint(*u).to_edwards(0)?;
    if a.is_small_order() || !a.is_torsion_free() {
        return None;
    }
    Some(a)
}

/// The Edwards key `A` (sign bit 0) of the X25519 public key `u`, or `None`
/// if `u` is not canonical, has no Edwards form, or is not in the
/// prime-order subgroup.
pub fn convert_mont(u: &[u8; 32]) -> Option<[u8; 32]> {
    edwards_of(u).map(|a| a.compress().to_bytes())
}

/// Whether `sig` is an XEdDSA signature of `msg` by the X25519 key `u`.
pub fn verify(u: &[u8; 32], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> bool {
    let Some(a) = edwards_of(u) else {
        return false;
    };
    let r: [u8; 32] = sig[..32].try_into().expect("32 bytes");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32 bytes");
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return false;
    };
    let h = challenge(&r, &a.compress().to_bytes(), msg);
    // R = sB − hA, compared as canonical encodings: a non-canonical R in
    // the signature never matches.
    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &-a, &s).compress();
    r_check.as_bytes().ct_eq(&r).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_x25519;
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use ed25519_dalek::{Signature, VerifyingKey};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_json::Value;

    const VECTORS: &str = include_str!("../tests/vectors/xeddsa.json");
    const LIBSIGNAL: &str = include_str!("../tests/vectors/xeddsa_libsignal.json");

    fn x25519_public(k: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*k)).to_bytes()
    }

    fn hex32(v: &Value) -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn hex64(v: &Value) -> [u8; 64] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// p = 2^255 − 19, little-endian.
    fn p_bytes() -> [u8; 32] {
        let mut p = [0xFF; 32];
        p[0] = 0xED;
        p[31] = 0x7F;
        p
    }

    /// The order of the group, q, little-endian.
    fn q_bytes() -> [u8; 32] {
        hex32(&Value::from(
            "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        ))
    }

    fn ed25519_verifies(a: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(a)
            .and_then(|k| k.verify_strict(msg, &Signature::from_bytes(sig)))
            .is_ok()
    }

    #[test]
    fn the_spec_vectors_sign_and_verify_byte_for_byte() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 8);
        let mut signs = [false; 2];
        for c in cases {
            let k = hex32(&c["k"]);
            let u = hex32(&c["u"]);
            let msg = bytes(&c["msg"]);
            let z = hex64(&c["z"]);
            let sig = hex64(&c["sig"]);
            let a = hex32(&c["ed_public"]);
            signs[c["e_sign"].as_u64().unwrap() as usize] = true;

            assert_eq!(calculate_key_pair(&k).0, a, "A of {}", c["k"]);
            assert_eq!(convert_mont(&u), Some(a), "convert_mont of {}", c["u"]);
            assert_eq!(sign_with_z(&k, &msg, &z), sig, "signature of {}", c["k"]);
            assert!(verify(&u, &msg, &sig));
            // What the specification promises, checked by another library.
            assert!(ed25519_verifies(&a, &msg, &sig));
        }
        assert_eq!(
            signs,
            [true, true],
            "both Edwards sign bits must be covered"
        );
    }

    #[test]
    fn libsignals_xeddsa_vector_is_reproduced() {
        let v: Value = serde_json::from_str(LIBSIGNAL).unwrap();
        let c = &v["xeddsa_fast_test"];
        let k = hex32(&c["k"]);
        let msg = bytes(&c["msg"]);
        let sig = hex64(&c["sig"]);
        let u = x25519_public(&k);
        assert_eq!(sign_with_z(&k, &msg, &hex64(&c["z"])), sig);
        assert!(verify(&u, &msg, &sig));
    }

    #[test]
    fn libsignals_sign_bit_variant_is_refused() {
        // libsignal carries the Edwards sign bit in the top bit of s; with
        // that bit set, s is not below q and the key is not A.
        let v: Value = serde_json::from_str(LIBSIGNAL).unwrap();
        let c = &v["libsignal_sign_bit_variant"];
        let u = hex32(&c["u"]);
        assert_eq!(x25519_public(&hex32(&c["k"])), u);
        let sig = hex64(&c["sig"]);
        assert_eq!(sig[63] & 0x80, 0x80);
        assert!(!verify(&u, &bytes(&c["msg"]), &sig));
    }

    #[test]
    fn a_fresh_signature_verifies_under_the_converted_key_as_ed25519() {
        for _ in 0..16 {
            let kp = generate_x25519();
            let msg = b"trino/device-dh/v1\0 some entry";
            let sig = sign(&kp.priv_bytes, msg);
            assert!(verify(&kp.pub_bytes, msg, &sig));
            let a = convert_mont(&kp.pub_bytes).unwrap();
            assert_eq!(a, calculate_key_pair(&kp.priv_bytes).0);
            assert_eq!(a[31] & 0x80, 0, "A has its sign bit at 0");
            assert!(ed25519_verifies(&a, msg, &sig));
        }
    }

    #[test]
    fn z_is_random_so_two_signatures_differ_and_a_seeded_generator_repeats() {
        let kp = generate_x25519();
        let one = sign(&kp.priv_bytes, b"m");
        let two = sign(&kp.priv_bytes, b"m");
        assert_ne!(one, two);
        assert!(verify(&kp.pub_bytes, b"m", &one) && verify(&kp.pub_bytes, b"m", &two));

        let a = sign_with_rng(&kp.priv_bytes, b"m", &mut ChaCha20Rng::from_seed([7; 32]));
        let b = sign_with_rng(&kp.priv_bytes, b"m", &mut ChaCha20Rng::from_seed([7; 32]));
        assert_eq!(a, b);
    }

    #[test]
    fn a_changed_bit_anywhere_fails() {
        let kp = generate_x25519();
        let msg = b"the entry".to_vec();
        let sig = sign(&kp.priv_bytes, &msg);
        for i in 0..SIGNATURE_LEN * 8 {
            let mut bad = sig;
            bad[i / 8] ^= 1 << (i % 8);
            assert!(!verify(&kp.pub_bytes, &msg, &bad), "signature bit {i}");
        }
        for i in 0..msg.len() * 8 {
            let mut bad = msg.clone();
            bad[i / 8] ^= 1 << (i % 8);
            assert!(!verify(&kp.pub_bytes, &bad, &sig), "message bit {i}");
        }
        assert!(!verify(&kp.pub_bytes, b"the entry and more", &sig));
        assert!(!verify(&kp.pub_bytes, b"", &sig));
    }

    #[test]
    fn another_key_fails() {
        let kp = generate_x25519();
        let other = generate_x25519();
        let sig = sign(&kp.priv_bytes, b"m");
        assert!(!verify(&other.pub_bytes, b"m", &sig));
        // The Edwards key itself, read as an X25519 key, is another key.
        let a = convert_mont(&kp.pub_bytes).unwrap();
        assert!(!verify(&a, b"m", &sig));
    }

    #[test]
    fn non_canonical_u_and_s_are_refused() {
        let kp = generate_x25519();
        let sig = sign(&kp.priv_bytes, b"m");

        // The top bit set: 2^255 or more, never a canonical u.
        let mut top_bit = kp.pub_bytes;
        top_bit[31] |= 0x80;
        assert!(!verify(&top_bit, b"m", &sig));
        assert_eq!(convert_mont(&p_bytes()), None, "u = p");
        let mut p_plus_one = p_bytes();
        p_plus_one[0] += 1;
        assert_eq!(convert_mont(&p_plus_one), None, "u = p + 1");
        assert_eq!(convert_mont(&[0xFF; 32]), None);

        // s + q verifies under the equation; it must be refused.
        let s = Scalar::from_canonical_bytes(sig[32..].try_into().unwrap()).unwrap();
        let q = q_bytes();
        let mut s_plus_q = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = s.as_bytes()[i] as u16 + q[i] as u16 + carry;
            s_plus_q[i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        let mut malleated = sig;
        malleated[32..].copy_from_slice(&s_plus_q);
        assert!(!verify(&kp.pub_bytes, b"m", &malleated));

        // A non-canonical R (y + p) never matches the canonical R check.
        let mut r_top = sig;
        r_top[31] ^= 0x80;
        assert!(!verify(&kp.pub_bytes, b"m", &r_top));
    }

    #[test]
    fn small_order_and_mixed_order_keys_are_refused() {
        // u = 0 → (0, −1), order 2; u = 1 → y = 0, order 4; u = p − 1 has no
        // Edwards form. The Montgomery u of the order-8 points:
        // 0xe0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
        // and 0x5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157.
        let mut low = vec![[0u8; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        }];
        for h in [
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        ] {
            low.push(hex::decode(h).unwrap().try_into().unwrap());
        }
        let mut minus_one = p_bytes();
        minus_one[0] -= 1;
        low.push(minus_one);
        for u in &low {
            assert_eq!(convert_mont(u), None, "u = {}", hex::encode(u));
        }

        // With a small-order A, sB − hA takes at most 8 values: a forger
        // would only have to guess. R = sB with h·A = identity is one of them.
        let s = Scalar::from_bytes_mod_order([3; 32]);
        let r = EdwardsPoint::mul_base(&s).compress();
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(r.as_bytes());
        forged[32..].copy_from_slice(s.as_bytes());
        for u in &low {
            assert!(!verify(u, b"m", &forged));
        }

        // An honest key plus a point of order 2 is no longer torsion-free.
        let kp = generate_x25519();
        let a = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(clamp_integer(kp.priv_bytes)));
        let torsion = CompressedEdwardsY(
            hex::decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .decompress()
        .unwrap();
        assert!(torsion.is_small_order());
        let mixed = (a + torsion).to_montgomery().to_bytes();
        assert_eq!(convert_mont(&mixed), None);
        let sig = sign(&kp.priv_bytes, b"m");
        assert!(!verify(&mixed, b"m", &sig));
    }
}
