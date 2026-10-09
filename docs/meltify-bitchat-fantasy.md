# meltify-bitchat (fantasy)

This is a sketch, not a shipped command. There is no `cmd/meltify-bitchat`, no
`internal/derive` labels, and no seedify `--to-bitchat`. Native BitChat
(iOS/Android) generates independent random keys and has no import path.
`bitchat-in-browser` has an nsec import UI, but it re-hashes the imported
bytes and would not round-trip this printout.

Do not confuse with **BChat** (Beldex), which meltify already prints as
`bchat:<66 hex>` from the CryptoNote 25-word seed.

## Why it is fantasy

BitChat identity is four long-term secrets plus a nickname:

| Piece | Curve | Native origin | Restores |
|---|---|---|---|
| Noise static | X25519 | random CryptoKit / Noise DH | mesh peer ID, fingerprint, Noise XX, courier seals |
| Signing key | Ed25519 | independent random | announces, packets, vouches |
| Nostr key | secp256k1 Schnorr | independent random | `nsec` / `npub`, relay DMs, location *account* |
| Device seed | 32 bytes | independent random | per-geohash / bridge Nostr via HMAC-SHA256 |
| Nickname | — | user-chosen | QR / announce display; not derived |

`nsec` is only the Nostr slice. A sibling CLI would have to invent a mapping
from the SSH Ed25519 seed, because BitChat specifies none.

## Invented KDF

All from the unlocked OpenSSH Ed25519 seed `S` (after `--subaccount` / `-s` if
any). Labels are meltify-native; seedify v1.36.0 has no BitChat domain.

```
noise    = X25519( SHA-256("bitchat:noise:"        || S) )   # clamped
sign     = Ed25519( SHA-256("bitchat:sign:"         || S) )
device   =          SHA-256("bitchat:device-seed:"  || S)
nostr    = NIP-06 of Mnemonic24(S)   # same nsec meltify-info already prints
peer-id  = SHA-256(noise_pub)[:8]
```

Using meltify’s existing NIP-06 nsec keeps one identity across Nostr clients.
A `bitchat:nostr:` domain hash would fork it from `meltify-info`.

`--subaccount camp` would run `ActivateSubaccount` first, then the same
labels, so camp vs default are different peer IDs.

## CLI shape

Sibling like `meltify-onion` / `meltify-info`: load the password-protected
key via `internal/sshkey` (no `meltify` binary). Default stdout dumps
secrets, same as `meltify` / `meltify-info`. A later `--public` could print
only peer ID, pubs, and npub.

Compact one-liner for a future `meltify-info` line, same idea as `bchat:`:

```
bitchat:<peer-id>
```

QR payload would still need a nickname (user-chosen, not derived) plus the
two public keys and npub.

## Example output

Voice matches `internal/termout`: private `-----BEGIN …-----` blocks first,
then public, then compact `label:` lines. Hex below is illustrative, not a
golden.

```
$ meltify-bitchat ~/.ssh/id_ed25519
```

```
-----BEGIN NOISE STATIC (X25519)-----
c8a1…32-byte hex…
-----END NOISE STATIC (X25519)-----


-----BEGIN ED25519 SIGNING SEED-----
3b91…32-byte hex…
-----END ED25519 SIGNING SEED-----


-----BEGIN DEVICE SEED (GEOHASH HMAC)-----
9e04…32-byte hex…
-----END DEVICE SEED (GEOHASH HMAC)-----


----- nSecKey / hexSecKey -----
nsec1q…
67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa
----- nSecKey / hexSecKey -----


-----BEGIN PEER ID-----
a1b2c3d4e5f60708
-----END PEER ID-----


-----BEGIN NOISE FINGERPRINT-----
a1b2c3d4e5f60708…64 hex of SHA-256(noise_pub)…
-----END NOISE FINGERPRINT-----


-----BEGIN NOISE PUBLIC KEY-----
5f0c…32-byte hex…
-----END NOISE PUBLIC KEY-----


-----BEGIN ED25519 SIGNING PUBLIC KEY-----
8d22…32-byte hex…
-----END ED25519 SIGNING PUBLIC KEY-----


----- nPubKey / hexPubKey -----
npub1q…
2d6b…64 hex…
----- nPubKey / hexPubKey -----

bitchat:a1b2c3d4e5f60708
```

### Block map

| Block | Restores |
|---|---|
| Noise static | mesh peer ID / fingerprint / Noise XX / courier seals |
| Ed25519 signing seed | announces, packets, vouches |
| Device seed | per-geohash / bridge Nostr identities |
| nsec | internet DMs / location account (meltify NIP-06, not native random) |

## Honesty constraints

- Native iOS/Android still cannot import any of this.
- `bitchat-in-browser` import treats nsec/hex as a master seed and does
  `blake2b("bitchat-nostr-key" || bytes)`, so this printout would not
  restore that client either.
- The 24-word MELT phrase is BIP-39 of `S`. BitChat never consumes BIP-39.
  The browser mnemonic path is not NIP-06 (Argon2id + BLAKE2b, then hashed
  again).
- Implementation pattern, if this ever stopped being fantasy: `cmd/meltify-bitchat`
  + `internal/app/bitchat` (name clash with Beldex `internal/app/bchat`) +
  goldens against `FixedSeed00to1f`. Direct `sshkey.LoadEd25519Key`. Do not
  import seedify.
