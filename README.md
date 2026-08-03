# meltify

`meltify` prints a compact, colored export from an Ed25519 OpenSSH private key:

- OpenSSH public key fingerprint
- OpenSSH public key with derived `npub` comment
- Nostr `npub` / hex public key
- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr `nsec` / hex secret key

## Install

**Homebrew** (macOS/Linux):

```sh
brew install ZenTenApp/tap/meltify
```

**Go install**:

```sh
go install github.com/ZenTenApp/meltify/cmd/meltify@latest
```

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

```sh
meltify ~/.ssh/id_ed25519 --brave-sync
```

`--brave-sync` prints only the MELT seed phrase with Brave Sync's daily 25th word appended.

## Subaccount

```sh
meltify ~/.ssh/id_ed25519 --subaccount account-name
meltify ~/.ssh/id_ed25519 -s account-name
```

Subaccounts derive a different deterministic Ed25519 key from the source key and subaccount name. The emitted OpenSSH private key keeps the same passphrase and uses bcrypt KDF rounds = 1.

## Beldex

`meltify-beldex` derives a deterministic Beldex seed and addresses from the same Ed25519 OpenSSH key material:

```sh
meltify-beldex ~/.ssh/id_ed25519
```

The 25-word CryptoNote seed is unprefixed. A future `meltify-monero` command should therefore produce the same 25-word seed from the same key when no `--subaccount` is used.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`.

## Completions and man page

Generate shell completions:

```sh
meltify completion bash
meltify completion zsh
meltify completion fish
meltify completion powershell
meltify-beldex completion bash
```

Generate a roff man page:

```sh
meltify man
meltify-beldex man```

## Notes

- Only Ed25519 OpenSSH private keys are supported.
- No QR output.
- Colors are enabled when stdout is a TTY and `NO_COLOR` is not set.
