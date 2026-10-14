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
go install github.com/ZenTenApp/meltify/cmd/meltify-pgp@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-onion@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-rsa@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-dkim@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-dnssec@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-i2p@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-wireguard@latest
go install github.com/ZenTenApp/meltify/cmd/meltify-jks@latest
```

`meltify-brave`, `meltify-beldex`, `meltify-monero`, and `meltify-polyseed` execute `meltify` internally, so `meltify` must be installed next to them or available in `PATH`. `meltify-info`, `meltify-pgp`, `meltify-onion`, `meltify-rsa`, `meltify-dkim`, `meltify-dnssec`, `meltify-i2p`, `meltify-wireguard`, and `meltify-jks` load the key themselves and do not need `meltify`.

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

The OpenSSH private key must be password-protected. Meltify prompts for that passphrase.

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

The output has two sections separated by a row of asterisks. The first is the default CryptoNote legacy section above. The second is the Unstoppable/Cake section: it starts with the 24-word MELT BIP39 phrase (restore this in Unstoppable), then the 25-word Cake/Feather seed that Unstoppable displays for that phrase, then the corresponding `4…` addresses. The Cake keys come from the BIP39 phrase with no Keccak (`m/44'/128'/0'/0/0`); the 25-word Cake seed is not the CryptoNote legacy seed printed in the first section.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`.

## Polyseed (Monero 16-word)

`meltify-polyseed` runs `meltify` internally, then derives the complete set of deterministic 16-word Monero polyseeds (Polyseed format) from the same Ed25519 OpenSSH key material:

```sh
meltify-polyseed ~/.ssh/id_ed25519
```

By default it emits every unique polyseed from the first possible birthday (the Polyseed era, November 2021) through today — one block per unique birthday period, labeled with the calendar-day range it covers (e.g. `2021-11-01 → 2021-12-01`), exactly like seedify's `--all-polyseeds`. Each polyseed embeds a creation date (the "birthday"). Use `--birthday YYYY-MM` to emit a single polyseed for that month together with its Monero primary address and subaddresses; the same key, subaccount, and birthday always produce the same phrase.

Because the polyseed birthday grid is ~30.44 days and drifts against calendar months, a `--birthday YYYY-MM` phrase (the 1st of the month at 00:00 UTC) can fall in the *previous* period, so it may differ from the all-polyseeds chunk covering most of that month — this matches seedify's own behavior.

The polyseed phrase is self-contained — restoring it in any standard Monero wallet reproduces the same keys — so no `--seed-offset` is offered (the polyseed format has no slot for a seed offset; that is a legacy 25-word concept).

It supports `--subaccount` / `-s`, `--birthday`, and the same completion/manpage commands as `meltify`.

## Info (full identity report)

`meltify-info` prints the original meltify identity export: a compact, colored report derived from a single Ed25519 OpenSSH private key:

- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr `nsec` / hex secret key
- OpenSSH public key fingerprint
- OpenSSH public key with derived `npub` comment
- Nostr `npub` / hex public key
- wallet addresses as `label:address` (EVM chains reuse the Ethereum `0x`; TON is Wallet V4R2 UQ at `m/44'/607'/0'`; Monero and Beldex use the 25-word CryptoNote legacy primary)
- BChat chat ID, printed after the chain list (not a crypto chain)

All forms come from the same master seed, so the SSH key, raw seed, and MELT phrase are the same secret in different encodings; the Nostr keys and BIP39 wallet addresses are deterministically derived from the MELT phrase. `meltify-info` loads the key itself and supports `--subaccount` / `-s` plus the same completion/manpage commands as `meltify`.

## PGP

`meltify-pgp` loads an Ed25519 OpenSSH private key and prints a deterministic ASCII-armored OpenPGP secret key (`gpg --import`). The primary RSA key is `[SC]` and the subkey is `[E]`. Creation time is 2020-01-01 UTC so the fingerprint is stable. `--name` and `--email` are required for the UID. `--bits` defaults to 4096 (2048 and 3072 are also accepted). The OpenPGP secret is always passphrase-protected; `--reuse-passphrase` reuses the SSH key passphrase.

```sh
meltify-pgp ~/.ssh/id_ed25519 --name "Alice" --email alice@example.com
```

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## Onion (Tor v3)

`meltify-onion` loads an Ed25519 OpenSSH private key and prints a deterministic Tor v3 `.onion` address. Pass `--output <dir>` to also write a Tor HiddenServiceDir (`hs_ed25519_secret_key`, `hs_ed25519_public_key`, `hostname`) that can be copied into `torrc` as `HiddenServiceDir`.

```sh
meltify-onion ~/.ssh/id_ed25519
meltify-onion ~/.ssh/id_ed25519 --output ./hidden_service
```

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## RSA

`meltify-rsa` loads an Ed25519 OpenSSH private key and prints a deterministic RSA private key. Default encoding is OpenSSH PEM. `--openssl-compatible` writes an encrypted PKCS#8 PEM instead (`openssl pkey -check`). `--bits` defaults to 4096 (2048 and 3072 are also accepted). The derived secret is always passphrase-protected; `--reuse-passphrase` reuses the SSH key passphrase. Pass `--output <path>` to write a `0600` file instead of stdout.

```sh
meltify-rsa ~/.ssh/id_ed25519
meltify-rsa ~/.ssh/id_ed25519 --output ~/.ssh/id_rsa_derived
meltify-rsa ~/.ssh/id_ed25519 --openssl-compatible --output key.pem
```

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## DKIM

`meltify-dkim` loads an Ed25519 OpenSSH private key and derives a deterministic DKIM RSA keypair. The private key is unencrypted PKCS#8 PEM (`BEGIN PRIVATE KEY`), not passphrase-protected. `--selector` defaults to `mail`. `--bits` defaults to 4096 (2048 and 3072 are also accepted). Pass `--domain` to write `config/dkim/<domain>/<selector>.private` (0600) and `.public` (the DNS TXT value). Pass `--output <path>` to write only the private key.

```sh
meltify-dkim ~/.ssh/id_ed25519 --domain example.com
meltify-dkim ~/.ssh/id_ed25519 --domain example.com --selector mail2026
meltify-dkim ~/.ssh/id_ed25519 --output /etc/opendkim/keys/mail.private
```

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## DNSSEC

`meltify-dnssec` loads an Ed25519 OpenSSH private key and derives a deterministic DNSSEC keypair for a zone. `--domain` is required. `--algorithm` selects the DNSSEC algorithm and defaults to `ED25519` (15); `RSASHA256` (8) is also supported. `--ksk` (default) uses DNSKEY flags 257; `--zsk` uses 256. `--bits` (default 4096) applies only to RSASHA256 and is ignored for ED25519. The zone name, algorithm, role, and bit size are mixed into the derivation, so each zone, algorithm, and role gets a distinct key.

By default it prints the public DNSKEY and DS records to stdout. Pass `--output <dir>` to write BIND-compatible files instead: `K<zone>.+<alg>+<keytag>.key` (0644), `.private` (0600, `Private-key-format: v1.3`), and `.ds` (0644, SHA-256).

```sh
meltify-dnssec ~/.ssh/id_ed25519 --domain example.com
meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --algorithm RSASHA256 --bits 4096
meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --ksk --output ./dnssec-keys
meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --zsk --output ./dnssec-keys
```

The `.private` file is stamped with the real current time (`Created`/`Publish`/`Activate`), so the file bytes change between runs even though the key material is deterministic. Not every resolver or registrar accepts algorithm 15; use `--algorithm RSASHA256` for maximum compatibility.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## I2P

`meltify-i2p` loads an Ed25519 OpenSSH private key and derives a deterministic I2P Destination (Ed25519 signing key plus X25519 encryption key). By default it prints the `.b32.i2p` address, the X25519 private scalar, and the Ed25519 seed. Pass `--output <dir>` to write the i2pd `keys.dat` file (`0600`) instead, suitable for a tunnel with `keys = keys.dat`.

```sh
meltify-i2p ~/.ssh/id_ed25519
meltify-i2p ~/.ssh/id_ed25519 --output ./i2p-keys
```

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## WireGuard

`meltify-wireguard` loads an Ed25519 OpenSSH private key and derives a deterministic WireGuard static keypair. It prints the private and public keys as standard base64, the same format produced by `wg genkey` / `wg pubkey`, ready to paste into a WireGuard `[Interface]` or `[Peer]` section.

```sh
meltify-wireguard ~/.ssh/id_ed25519
```

The private key is secret key material: it is printed to stdout, so do not pipe it to logs or untrusted commands.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

## Java KeyStore

`meltify-jks` loads an Ed25519 OpenSSH private key and derives a deterministic RSA private key plus self-signed X.509 certificate, then writes a password-protected Java KeyStore (`.jks`) to `--output` (`0600`). `--alias` and `--output` are required; `--dn` defaults to `CN=<alias>` and `--validity` to 10000 days. It also prints the Android signing secrets (keystore base64, alias, store password, key password) for CI/CD.

```sh
meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks
meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --dn "CN=Zenten, OU=Mobile, O=ZenTen"
```

The keystore is always password-protected: enter a new passphrase, pass `--reuse-passphrase` to reuse the SSH key passphrase, or supply `--store-password` (mutually exclusive with `--reuse-passphrase`). The key entry defaults to the store password; use `--key-password` to set a separate password. Both passwords must be non-empty. These flags do not replace the SSH key passphrase prompt.

```bash
meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --store-password "$STORE_PASSWORD" --key-password "$KEY_PASSWORD"
```

Password flags can expose secrets in shell history and process listings; prefer the interactive prompt when possible.

It supports `--subaccount` / `-s` and the same completion/manpage commands as `meltify`. Like `meltify-info`, it loads the key itself and does not need the `meltify` binary.

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
meltify-pgp completion bash
meltify-onion completion bash
meltify-rsa completion bash
meltify-dkim completion bash
meltify-dnssec completion bash
meltify-i2p completion bash
meltify-wireguard completion bash
meltify-jks completion bash
```

Generate a roff man page:

```sh
meltify man
meltify-brave man
meltify-beldex man
meltify-monero man
meltify-polyseed man
meltify-info man
meltify-pgp man
meltify-onion man
meltify-rsa man
meltify-dkim man
meltify-dnssec man
meltify-i2p man
meltify-wireguard man
meltify-jks man
```

## Notes

- Only Ed25519 OpenSSH private keys are supported.
- No QR output.
- Colors are enabled when stdout is a TTY and `NO_COLOR` is not set.
