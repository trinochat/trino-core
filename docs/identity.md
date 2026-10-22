# Identity, prekeys and bundles

Why the identity module rotates, keeps and checks keys the way it does.

| Topic | Code |
| --- | --- |
| [Signed prekey rotation](#spk-rotation) | `SPK_ROTATION_SECS`, `rotate_signed_prekey_if_due` |
| [Retention of retired prekeys](#spk-retention) | `SPK_RETENTION_SECS`, `RetiredSignedPreKey`, `Identity::retired_signed_prekeys`, `signed_prekey_by_id` |
| [Expiry of retired prekeys](#spk-expiry) | `rotate_signed_prekey_if_due` |
| [Identity binding signature](#identity-binding) | `PublicBundle::id_sig`, `identity_signing_bytes`, `verify_bundle_binding` |
| [Non-contributory DH keys](#non-contributory-dh) | `x25519_derive_shared` |

## <a id="spk-rotation"></a>Signed prekey rotation

Rotation is what bounds the damage of a leaked signed prekey. Without it, one compromised signed prekey exposes every initial message ever sent to us.

`rotate_signed_prekey_if_due` generates a fresh signed prekey once the current one is `SPK_ROTATION_SECS` old: 2 days, as Signal does. The new key takes the next id after every id still held, and the outgoing key is retired at `now` (see [retention](#spk-retention)).

It returns `true` when anything changed, a rotation or an [expiry](#spk-expiry), so the caller knows to re-seal the vault and republish its bundle.

## <a id="spk-retention"></a>Retention of retired prekeys

Retention is what makes rotation safe. Bundles are exchanged out of band and cached by the peer, so a peer may legitimately hand us an older `spk_id` long after we rotated. Dropping the old key at once would break those peers, and every auto-heal re-handshake from them.

A retired key stays usable for `SPK_RETENTION_SECS` (30 days), counted from `RetiredSignedPreKey::retired_at`, the moment it stopped being current, and not from its creation. Until that moment the key was in the bundle we hand out, so it is exactly the one peers have cached. A device that stays locked for weeks rotates late, and the key it retires then is the one every peer still holds.

`signed_prekey_by_id` finds the current key or any retired key still held. That is what lets a peer holding an older cached bundle complete, or re-complete, a handshake. The responder's ratchet must then start from the prekey the handshake named, which `x3dh::respond` returns as `spk_keypair`.

## <a id="spk-expiry"></a>Expiry of retired prekeys

Forward secrecy only improves once the retired private key is gone, so expiring retired keys matters as much as rotating. `rotate_signed_prekey_if_due` drops every retired key whose retention has run out, in the same call that rotates. A retired key is therefore held until the first call after its window closes.

## <a id="identity-binding"></a>Identity binding signature

`PublicBundle::id_sig` is the identity key's (`ik_sign`) Ed25519 signature over `ik_dh_pub ‖ nostr_pub`, the 64 bytes that `identity_signing_bytes` builds. It binds the DH and Nostr keys to the identity key, so a man in the middle cannot swap them.

- `verify_bundle` only checks the signature on the signed prekey.
- `verify_bundle_binding` also checks `id_sig`. Without it, a man in the middle could swap the DH key at first contact and the fingerprint would not catch it.

`verify_bundle_binding` is required for every bundle that becomes a contact: pasted or scanned bundles and group members alike. The admin's roster signature does not vouch for a member's keys, since it only proves what the admin claims, and any contact can be the admin of a group of their own. Roster v2 therefore carries each member's own `id_sig`, and `group::validate_roster` checks it with `verify_bundle_binding`.

Bundles made before the binding existed parse with an empty `id_sig`, the default when the field is absent, and `verify_bundle_binding` rejects them.

## <a id="non-contributory-dh"></a>Non-contributory DH keys

A low-order, or otherwise non-contributory, peer public key forces a predictable shared secret that the attacker knows. As defence in depth, `x25519_derive_shared` checks `was_contributory()` and, when that fails, returns 32 random bytes instead of the shared secret. The session derived from it then fails to agree, instead of running on a key the attacker knows. An honest peer's key is always contributory, so this never affects the honest path.
