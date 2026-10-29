//! P1: messages that no relay can tie to who sends them or to whom
//! (`research_notes/P1 metadatos/diseno.md` and `diseno-vinculacion.md`).
//!
//! Each message travels as a gift wrap signed by a one-time key and sealed
//! with NIP-44 v2 to a **mailbox**: a secp256k1 public key that both sides
//! derive and no third party can tie to an identity. This module holds the
//! pure parts; the app owns the relays, the clock and the storage.
//!
//! - [`mailbox`]: the mailbox derivations (design P1 §3).
//! - [`wire`]: the inner frame, its steps, MAC and proof of work (§2.2-§2.3).

pub mod mailbox;
pub mod wire;
