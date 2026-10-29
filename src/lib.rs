//! Trino Chat protocol core.
//!
//! Everything security-relevant and portable lives here: identity and public
//! bundles, the X3DH handshake, the Double Ratchet, the message envelope, group
//! rosters, the sealed vault, TOTP, and call-signal validation.
//!
//! The crate is intentionally **pure** — no sockets, no HTTP, no async runtime,
//! no UI, no platform APIs. That boundary exists for two reasons:
//!
//! 1. **Auditability.** A reviewer can read this crate alone to assess the
//!    cryptography, without wading through application plumbing.
//! 2. **Reuse.** Every client binds to the same implementation instead of
//!    reimplementing the protocol per platform (desktop today, the Flutter
//!    mobile client over FFI next).
//!
//! Transport (Nostr relays), attachment storage and app state deliberately live
//! in the client, not here — the protocol does not care how bytes are carried.

// The `test-kdf` feature (Cargo.toml) weakens the vault's KDF for the
// tests of the apps that use this crate. A release build never has it.
#[cfg(all(feature = "test-kdf", not(debug_assertions)))]
compile_error!("the test-kdf feature is for tests only: it must never reach a release build");

pub mod call_signal;
pub mod crypto;
pub mod envelope;
pub mod group;
pub mod identity;
pub mod kdf;
pub mod kem;
pub mod kit;
pub mod mldsa;
pub mod nip44;
pub mod p1;
pub mod pq_spk;
pub mod pqxdh;
pub mod ratchet;
pub mod totp;
pub mod vault;
pub mod vault_v3;
pub mod x3dh;
