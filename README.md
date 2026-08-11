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
```

`meltify-brave`, `meltify-beldex`, `meltify-monero`, and `meltify-polyseed` execute `meltify` internally, so `meltify` must be installed next to them or available in `PATH`.

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

`meltify-beldex` runs `meltify` internally, then derives a deterministic Beldex seed and addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-beldex ~/.ssh/id_ed25519
```

The 25-word CryptoNote seed is unprefixed. `meltify-monero` produces the same 25-word seed from the same key when no `--subaccount` is used.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`.

## Monero

`meltify-monero` runs `meltify` internally, then derives a deterministic Monero legacy seed and addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-monero ~/.ssh/id_ed25519
```

Without `--subaccount`, the 25-word Monero legacy seed is identical to the Beldex 25-word seed from the same key, because both are the unprefixed CryptoNote legacy mnemonic of the raw Ed25519 seed. `meltify-monero` additionally supports `--seed-offset <passphrase>` to derive Monero keys from the seed with an Electrum seed offset.

It supports `--subaccount` / `-s`, `--seed-offset`, and the same completion/manpage commands as `meltify`.

## Polyseed (Monero 16-word)

`meltify-polyseed` runs `meltify` internally, then derives a deterministic 16-word Monero polyseed (Polyseed format) and Monero addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-polyseed ~/.ssh/id_ed25519
```

The polyseed embeds a creation date (the "birthday"), which defaults to January 1 of the current year (matching the seedify CLI). Override it with `--birthday YYYY-MM`; the same key, subaccount, and birthday always produce the same phrase. A `--seed-offset <passphrase>` is also supported for Feather-compatible wallet seed offsets.

It supports `--subaccount` / `-s`, `--seed-offset`, `--birthday`, and the same completion/manpage commands as `meltify`.

Generate shell completions:

```sh
meltify completion bash
meltify completion zsh
meltify completion fish
meltify completion powershell
meltify-brave completion bash
meltify-beldex completion bash
meltify-monero completion bash
meltify-polyseed completion bash
```

Generate a roff man page:

```sh
meltify man
meltify-brave man
meltify-beldex man
meltify-monero man
meltify-polyseed man
```

## Notes

- Only Ed25519 OpenSSH private keys are supported.
- No QR output.
- Colors are enabled when stdout is a TTY and `NO_COLOR` is not set.
