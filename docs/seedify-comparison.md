# Seedify vs meltify

Comparison of [seedify v1.36.0](https://github.com/ZenTenApp/seedify) (read from the Go module cache) against this repo. Meltify does **not** import seedify. `internal/derive` reimplements the APIs meltify actually calls; golden values in `internal/derive/golden.go` were captured from seedify v1.36.0 for the fixed Ed25519 seed `00..1f`.

Seedify is one CLI with many flags. Meltify is a family of sibling binaries (`cmd/meltify-*`) that share `internal/derive`.

## Already ported

| Seedify | Meltify |
|---------|---------|
| default 24-word BIP39 | `meltify-info` (MELT phrase) |
| `--brave` | `meltify-brave` |
| `--xmr-legacy` | `meltify-monero` |
| `--bdx` | `meltify-beldex` |
| `--xmr` + `--all-polyseeds` / `--polyseed-year` / `--polyseed-month` | `meltify-polyseed` (default = all unique birthdays; `--birthday YYYY-MM` for one month) |
| `--nostr` + chain addresses | `meltify-info` |
| `--to-pgp` | `meltify-pgp` |
| `--to-onion` | `meltify-onion` |
| `--to-rsa` + `--openssl-compatible` | `meltify-rsa` |
| `--to-dkim` | `meltify-dkim` (`--selector` / `--domain`) |

`meltify-info` prints native SegWit BTC, BCH, ETH + EVM aliases, SOL, TRX, LTC, DOGE, ATOM, XRP, XLM, SUI, TON V4R2, silent payments, Monero and Beldex legacy primaries, plus BChat.

## Meltify-ahead

Features meltify has that seedify v1.36.0 does not:

- Bitcoin Cash (`bitcoincash:…` at `m/44'/145'/0'/0/0`)
- TON Wallet V4R2 UQ at `m/44'/607'/0'`
- BChat chat ID
- `--subaccount` / `-s` on every sibling CLI

## Missing dedicated modes

Exclusive seedify one-shot flags with no meltify sibling. There is **no** `--to-age` in seedify v1.36.0.

| Seedify | What it does |
|---------|--------------|
| `--to-dnssec` | BIND RSASHA256 KSK/ZSK (`--dnssec-domain`, `--dnssec-ksk` / `--dnssec-zsk`) |
| `--to-i2p` | I2P destination (Ed25519 signing + X25519 encryption) + `keys.dat` |
| `--to-wireguard` | WireGuard static keypair (wg base64) |
| `--to-jks` | RSA + self-signed cert as a Java KeyStore |
| `--sshkey-qr` | One-line OpenSSH private key + terminal QR |
| `--brain-bunker` + `--brain-bunker-kdf-rounds` + `--brain-bunker-key-passphrase` | Ephemeral Ed25519 SSH key from a bunker secret; all later output uses that key |

## Missing Nostr / profile publishing

- `--zentenprofile` — public keys and addresses as DNS JSON
- `--kind10002` + `--publish` — Kind 10002 relay-list event
- `--publish` + `--blockchains` — Kind 0 address tags to relays

## Missing wallet / mnemonic surface

### Chains

Seedify prints these; meltify does not:

- **Zcash** transparent t-addr (`--zec`)
- **Noble** (`noble1…`, same BIP44 path as Cosmos, different HRP)

### Bitcoin extras

Meltify-info only prints native SegWit `bc1q`. Seedify `--btc` also emits:

- legacy P2PKH (`1…`) and P2SH-SegWit (`3…`)
- WIF private keys
- master xpub/xprv and account xpub / ypub / zpub (and private)
- BIP48 1-of-1 multisig (legacy / nested / native) + Ypub / Zpub
- BIP47 PayNym (payment code + notification address)
- master fingerprint

### Mnemonic and derivation knobs

- BIP39 lengths **12 / 15 / 18 / 21** (`--words`) — meltify only does 24 + polyseed 16
- `--language` / `-l` (non-English BIP39)
- `--bip39-passphrase` (wallet 25th word; not the same as brain-bunker)
- `ToMnemonicWithPrefix` domain separation
- Feather `--xmr-seed-offset` — `applyMoneroSeedOffset` exists in `internal/derive/cryptonote.go` but every public API passes `""`
- RSA **source** keys (`DeriveEd25519KeyFromRSA`) — meltify is Ed25519-only
- `seedify brave-sync-25th --date` standalone command (library exists; only `meltify-brave` uses “today”)
- `~/.seedify.ini` color overrides (`--config`)

## Suggested next ports

If more siblings follow the pgp/onion pattern (`cmd/meltify-X`, `internal/app/X`, goldens vs seedify v1.36.0 `FixedSeed00to1f`, no seedify import):

1. **dnssec, i2p, wireguard, jks** — dedicated binaries
2. **brain-bunker / sshkey-qr** — cross-cutting flags, not new binaries
3. Wallet extras (Zcash, Noble, Bitcoin WIF/xpub/PayNym) only if `meltify-info` should grow toward seedify `--full`

Do not keep a seedify module dependency. Take inspiration from the v1.36.0 source and lock behavior with in-tree goldens.
