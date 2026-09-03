# meltify

`meltify` extracts the raw 32-byte Ed25519 seed from an OpenSSH private key and prints it as lowercase hex.

This output is secret key material. Do not pipe it to logs or untrusted commands.

## Install

**Homebrew** (macOS/Linux):

```sh
brew install ZenTenApp/tap/meltify
```

**Go install**:

```sh
go install github.com/ZenTenApp/meltify/cmd/meltify@latest

go install github.com/ZenTenApp/meltify/cmd/meltify-brave@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-beldex@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-monero@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-polyseed@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-info@latest
```

`meltify-brave`, `meltify-beldex`, `meltify-monero`, and `meltify-polyseed` execute `meltify` internally, so `meltify` must be installed next to them or available in `PATH`. `meltify-info` loads the key itself and does not need `meltify`.

**Docker**:

```sh
docker run --rm -v ~/.ssh:/root/.ssh:ro ghcr.io/zentenapp/meltify /root/.ssh/id_ed25519
```

**Binary releases**: download from the
[Releases](https://github.com/ZenTenApp/meltify/releases) page.

## Usage

```sh
meltify ~/.ssh/id_ed25519
```

Or read the private key from stdin:

```sh
cat ~/.ssh/id_ed25519 | meltify
```

Encrypted keys prompt for the existing SSH key passphrase.

## Brave Sync

`meltify-brave` runs `meltify` internally, then prints only the MELT seed phrase with Brave Sync's daily 25th word appended.

```sh
meltify-brave ~/.ssh/id_ed25519
```

## Subaccount

```sh
meltify ~/.ssh/id_ed25519 --subaccount subaccount-label
meltify ~/.ssh/id_ed25519 -s subaccount-label
```

Subaccounts derive a different deterministic Ed25519 key from the source key and an arbitrary subaccount label string. The emitted OpenSSH private key keeps the same passphrase and uses bcrypt KDF rounds = 1.

## Beldex

`meltify-beldex` runs `meltify` internally, then derives a deterministic Beldex seed, addresses, and BChat chat ID from the same Ed25519 OpenSSH key material:

```sh
meltify-beldex ~/.ssh/id_ed25519
```

The 25-word CryptoNote seed is unprefixed. `meltify-monero` produces the same 25-word seed from the same key when no `--subaccount` is used.

The BChat chat ID is the X25519 public key of the CryptoNote legacy seed — the exact 32 bytes the printed 25-word phrase encodes — prefixed with the DJB type tag `0xBD` (66 hex chars, e.g. `bd27b58b…3952`), matching how BChat derives it when the phrase is restored (`cryptoSignSeedKeypair` → `convertKeyPairEd25519ToCurve25519` → prepend `0xBD`). Deriving it from the raw (unscReduced) seed would disagree with BChat for every seed that does not reduce to itself.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`.

## Monero

`meltify-monero` runs `meltify` internally, then derives a deterministic Monero legacy seed and addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-monero ~/.ssh/id_ed25519
```

Without `--subaccount`, the 25-word Monero legacy seed is identical to the Beldex 25-word seed from the same key, because both are the unprefixed CryptoNote legacy mnemonic of the raw Ed25519 seed.

It supports `--subaccount` / `-s`, and the same completion/manpage commands as `meltify`.

## Polyseed (Monero 16-word)

`meltify-polyseed` runs `meltify` internally, then derives a deterministic 16-word Monero polyseed (Polyseed format) and Monero addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-polyseed ~/.ssh/id_ed25519
```

The polyseed embeds a creation date (the "birthday"), which defaults to January 1 of the current year (matching the seedify CLI). Override it with `--birthday YYYY-MM`; the same key, subaccount, and birthday always produce the same phrase. A `--seed-offset <passphrase>` is also supported for Feather-compatible wallet seed offsets.

It supports `--subaccount` / `-s`, `--seed-offset`, `--birthday`, and the same completion/manpage commands as `meltify`.

## Info (full identity report)

`meltify-info` prints the original meltify identity export: a compact, colored report derived from a single Ed25519 OpenSSH private key:

- OpenSSH public key fingerprint
- OpenSSH public key with derived `npub` comment
- Nostr `npub` / hex public key
- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr `nsec` / hex secret key
- wallet addresses: bitcoin (bc1), ethereum, solana, tron

All forms come from the same master seed, so the SSH key, raw seed, and MELT phrase are the same secret in different encodings; the Nostr keys and the four wallet addresses are deterministically derived from the MELT phrase via the standard BIP84/BIP44/SLIP-0010 paths (`bc1q…` native segwit, `0x…` Ethereum, Base58 Solana, `T…` Tron). `meltify-info` loads the key itself and supports `--subaccount` / `-s` plus the same completion/manpage commands as `meltify`.

## Completions and man page

```sh
meltify completion bash
meltify completion zsh
meltify completion fish
meltify completion powershell
meltify-brave completion bash
meltify-beldex completion bash
meltify-monero completion bash
meltify-polyseed completion bash
meltify-info completion bash
```

Generate a roff man page:

```sh
meltify man
meltify-brave man
meltify-beldex man
meltify-monero man
meltify-polyseed man
meltify-info man
```

## Notes

- Only Ed25519 OpenSSH private keys are supported.
- No QR output.
- Colors are enabled when stdout is a TTY and `NO_COLOR` is not set.
