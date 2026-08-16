# trino-core

The protocol and cryptography core of [Trino Chat](https://github.com/trinochat):
X3DH key agreement, a Double Ratchet, identity and prekey management, the
message envelope format, group rosters, TOTP, and a sealed local vault.

**This crate is pure.** No networking, no async runtime, no UI, no platform
APIs, no filesystem. It takes bytes and returns bytes. Everything that performs
I/O lives in the application, not here.

That is a deliberate constraint, and it buys three things: the security-relevant
code can be read and audited on its own; every client can share one
implementation instead of writing the protocol twice; and the test suite runs in
seconds with no fixtures, no network and no mocks.

> **Not affiliated with [Trino](https://trino.io), the distributed SQL query
> engine.** Different project, different field.

## Status

**Working, tested, and not externally audited.** Do not deploy this to protect
anyone who is actually at risk until that changes. An independent audit is the
single most valuable thing this crate is missing, and it is the next thing being
pursued.

## What is implemented

- **X3DH** key agreement over X25519, with signed prekeys and one-time prekeys.
  Signed prekeys rotate; retired ones are retained for a grace window so peers
  holding a cached bundle are not stranded mid-rotation.
- **Double Ratchet** with out-of-order and skipped-message handling. Decryption
  is transactional: the state is snapshotted and rolled back on any failure, so
  a tampered, replayed or undecryptable message can never corrupt a session.
  Ciphertext from a completed chain is classified as a replay rather than
  mistaken for a new ratchet step, and banked message keys are bounded globally
  so a peer cannot grow persisted state without limit.
- **Sealed vault** — AES-GCM over a PBKDF2-derived key, holding the identity and
  its prekeys.
- **Envelope, groups, TOTP and call signalling** — the wire formats shared by
  every client, with validation that rejects unknown fields and oversized
  payloads.

Secrets are zeroized on drop.

## Dependencies and licensing

Every dependency is permissively licensed, and that is enforced in CI rather
than left to good intentions — see [`deny.toml`](./deny.toml). The reason is
concrete: [libsignal](https://github.com/signalapp/libsignal) is AGPL-3.0 with
no exceptions and no commercial licence on offer, so a product that needs modern
ratcheting either adopts AGPL wholesale or reimplements the protocol — which is
exactly where subtle, exploitable mistakes live.

This crate is AGPL-3.0 too, but its permissive dependency tree means the
copyright holder can also grant a commercial licence for uses the AGPL does not
suit. A single copyleft dependency would take that option away permanently.

## Usage

```toml
[dependencies]
trino-core = { git = "https://github.com/trinochat/trino-core" }
```

Not published to crates.io yet; the wire format is not frozen and versions there
cannot be withdrawn.

## Tests

```bash
cargo test
```

The suite covers the protocol properties that matter rather than line coverage:
out-of-order delivery across a DH step, replay classification after a state
reload, tampered ciphertext, prekey rotation with a stale cached bundle, and
recovery of a session sealed by an older version of the crate.

## Contributing

Reviewing the cryptographic code is the single most valuable contribution.

Security issues: **do not open a public issue.** Use GitHub's *Report a
vulnerability* button on the Security tab, which opens a private advisory.

## Licence

**GNU AGPL-3.0-only** — see [`LICENSE`](./LICENSE). A separate commercial
licence is available from the copyright holder.
