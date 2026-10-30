# meltify-bitchat

`meltify-bitchat` derives a deterministic BitChat identity from an Ed25519
OpenSSH private key. It is a sibling of `meltify-onion` / `meltify-wireguard`:
it loads the key itself through `internal/sshkey` and does not need the
`meltify` binary.

```sh
meltify-bitchat ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519 | meltify-bitchat
meltify-bitchat ~/.ssh/id_ed25519 --subaccount subaccount-label
```

This output is secret key material. Do not pipe it to logs or untrusted
commands.

Do not confuse with **BChat** (Beldex), which meltify already prints as
`bchat:<66 hex>` from the CryptoNote 25-word seed in `meltify-info`.

## What BitChat stores

BitChat identity is four long-term secrets plus a nickname:

| Piece | Curve | Native origin | Restores |
|---|---|---|---|
| Noise static | X25519 | random CryptoKit / Noise DH | mesh peer ID, fingerprint, Noise XX, courier seals |
| Signing key | Ed25519 | independent random | announces, packets, vouches |
| Nostr key | secp256k1 Schnorr | independent random | `nsec` / `npub`, relay DMs, location *account* |
| Device seed | 32 bytes | independent random | per-geohash / bridge Nostr via HMAC-SHA256 |
| Nickname | — | user-chosen | QR / announce display; not derived |

## KDF

All from the unlocked OpenSSH Ed25519 seed `S` (after `--subaccount` / `-s` if
any). Labels are meltify-native; BitChat specifies no mapping from an SSH seed
and seedify v1.36.0 has no BitChat domain.

```
noise    = X25519( SHA-256("bitchat:noise:"        || S) )   # clamped, RFC 7748 §5
sign     = Ed25519( SHA-256("bitchat:sign:"         || S) )
device   =          SHA-256("bitchat:device-seed:"  || S)
nostr    = NIP-06 of Mnemonic24(S)   # same nsec meltify-info already prints
peer-id  = SHA-256(noise_pub)[:8]
```

Using meltify’s existing NIP-06 nsec keeps one identity across Nostr clients; a
`bitchat:nostr:` domain hash would fork it from `meltify-info`.

`--subaccount camp` runs `ActivateSubaccount` first, then the same labels, so
camp and default are different peer IDs.

The implementation lives in `internal/derive/bitchat.go` (`derive.BitChat`) and
`internal/app/bitchat` (CLI), with `cmd/meltify-bitchat` as the entrypoint.

## Example output

Voice matches `internal/termout`: private `-----BEGIN …-----` blocks first,
then public, then the compact `label:` line. The values below come from the
fixed test seed `FixedSeed00to1f`.

```
$ meltify-bitchat ~/.ssh/id_ed25519
```

```
-----BEGIN NOISE STATIC (X25519)-----
e0b9951e884c7a169dcd695a4e39c9575b054d9223d644c53a3b0fa6a064b948
-----END NOISE STATIC (X25519)-----


-----BEGIN ED25519 SIGNING SEED-----
4bd0172690ab8efdba9d8b6dfb5d2bbc34200b17224a774334bf85944d3098ee
-----END ED25519 SIGNING SEED-----


-----BEGIN DEVICE SEED (GEOHASH HMAC)-----
6a571963d950bb247f71aeae02908596e702405a63906a462df7ac7f59776310
-----END DEVICE SEED (GEOHASH HMAC)-----


----- nSecKey / hexSecKey -----
nsec1wnrq2ka38vxtsn3j83s3td7xsdlxhrzk8w8qyunykmluk66lz64slqplsa
74c6055bb13b0cb84e323c6115b7c6837e6b8c563b8e027264b6ffcb6b5f16ab
----- nSecKey / hexSecKey -----


-----BEGIN PEER ID-----
dd5ebd8bac8d78b2
-----END PEER ID-----


-----BEGIN NOISE FINGERPRINT-----
dd5ebd8bac8d78b28a7f926c94409ecd26a132303fe374086c98cb2d9948dcc6
-----END NOISE FINGERPRINT-----


-----BEGIN NOISE PUBLIC KEY-----
5bb97b737ce034880d1a550c6dcdafefe7ae725942175fb441c59d7e82ceca26
-----END NOISE PUBLIC KEY-----


-----BEGIN ED25519 SIGNING PUBLIC KEY-----
e137abb37aae838e9c35d4e6d0339c6e2be385df2778fe32de66721941874d05
-----END ED25519 SIGNING PUBLIC KEY-----


----- nPubKey / hexPubKey -----
npub102xk3gvg50prsrgm76ksy8nh6enrsgwpqgr3hku4g204z364lnns533vq7
7a8d68a188a3c2380d1bf6ad021e77d6663821c102071bdb95429f514755fce7
----- nPubKey / hexPubKey -----


bitchat:dd5ebd8bac8d78b2
```

### Block map

| Block | Restores |
|---|---|
| Noise static | mesh peer ID / fingerprint / Noise XX / courier seals |
| Ed25519 signing seed | announces, packets, vouches |
| Device seed | per-geohash / bridge Nostr identities |
| nsec | internet DMs / location account (meltify NIP-06, not native random) |
| Peer ID | compact one-liner (`bitchat:<peer-id>`), same idea as `bchat:` |

## Golden values

The `bitchat:*` labels are meltify-native, so the goldens in
`internal/derive/golden.go` (`GoldenBitChat*`) were computed independently from
the formula above — Python `hashlib` plus a from-scratch RFC 7748 X25519 — not
captured from seedify, and cross-checked against
`internal/derive/bitchat_test.go`. The `nsec` / `npub` slice is
`GoldenNsec` / `GoldenNpub` by construction, because it is NIP-06 of
`GoldenMnemonic24`.

## Honesty constraints

- Native iOS/Android still cannot import any of this; the labels are invented
  and BitChat does not specify them.
- `bitchat-in-browser` import treats nsec/hex as a master seed and does
  `blake2b("bitchat-nostr-key" || bytes)`, so this printout would not
  restore that client either.
- The 24-word MELT phrase is BIP-39 of `S`. BitChat never consumes BIP-39.
  The browser mnemonic path is not NIP-06 (Argon2id + BLAKE2b, then hashed
  again).
- The nickname is user-chosen and is not derived; a QR payload would need it
  alongside the two public keys and the npub.
- The derived identity is cryptographically linked to the source SSH key:
  compromising either key compromises both.

## Future work

- `--public` to print only the peer ID, public keys, and npub.
- A `bitchat:<peer-id>` line in `meltify-info`, next to `bchat:`.
