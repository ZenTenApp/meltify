// Package pgp provides the meltify-pgp CLI executable logic.
package pgp

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	binaryName = "meltify-pgp"

	// secretKeyFileMode is the permission used when writing the OpenPGP secret
	// key to --output. It is owner read/write only.
	secretKeyFileMode = 0o600
)

// Execute runs the meltify-pgp CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount      string
		name            string
		email           string
		output          string
		bits            int
		reusePassphrase bool
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export an OpenPGP secret key from an Ed25519 OpenSSH key",
		Long: `meltify-pgp derives a deterministic OpenPGP RSA secret key from an Ed25519 OpenSSH private key.

The output is an ASCII-armored PGP PRIVATE KEY BLOCK importable with gpg --import:
a primary rsa key with [SC] usage and an encryption subkey with [E] usage.
The creation timestamp is 2020-01-01 UTC so the OpenPGP fingerprint is stable.

By default the secret key is printed to stdout. Pass --output <path> to write it
to a file (0600) instead. The matching ASCII-armored PGP PUBLIC KEY BLOCK is
always printed to stdout so it can be shared or imported on its own.

The OpenSSH private key must be password-protected; meltify-pgp prompts for that
passphrase. The OpenPGP secret is always passphrase-protected: enter a new
passphrase, or pass --reuse-passphrase to reuse the SSH key passphrase. Use
--subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-pgp ~/.ssh/id_ed25519 --name "Alice" --email alice@example.com
  meltify-pgp ~/.ssh/id_ed25519 --name "Alice" --email alice@example.com --output secret.asc
  cat ~/.ssh/id_ed25519 | meltify-pgp --name "Alice" --email alice@example.com
  meltify-pgp ~/.ssh/id_ed25519 --name "Alice" --email alice@example.com --subaccount subaccount-label
  meltify-pgp ~/.ssh/id_ed25519 --name "Alice" --email alice@example.com --reuse-passphrase`,
		Version:      info.String(),
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && stdin == os.Stdin {
				if fi, statErr := os.Stdin.Stat(); statErr == nil && (fi.Mode()&os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			keyPath := "-"
			if len(args) > 0 {
				keyPath = args[0]
			}
			return runWithOptions(keyPath, subaccount, name, email, output, bits, reusePassphrase, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&name, "name", "", "Full name for the OpenPGP UID")
	rootCmd.Flags().StringVar(&email, "email", "", "Email address for the OpenPGP UID")
	rootCmd.Flags().StringVar(&output, "output", "", "Write the OpenPGP secret key to this path (0600) instead of stdout")
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultPGPBits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.Flags().BoolVar(&reusePassphrase, "reuse-passphrase", false, "Reuse the source SSH key passphrase to protect the OpenPGP secret; requires a password-protected source key")
	_ = rootCmd.MarkFlagRequired("name")
	_ = rootCmd.MarkFlagRequired("email")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, name, email, output string, bits int, reusePassphrase bool, stdin io.Reader) error {
	if err := derive.ValidPGPBits(bits); err != nil {
		return fmt.Errorf("invalid --bits: %w", err)
	}

	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	passphrase, err := readOutputPassphrase(reusePassphrase, material.SourcePass)
	if err != nil {
		return fmt.Errorf("could not read PGP passphrase: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for PGP (this may take a moment)...\n", bits)

	keys, err := derive.PGP(material.Key, bits)
	if err != nil {
		return fmt.Errorf("could not derive PGP keypair: %w", err)
	}

	secretBytes, err := encodeArmoredPrivateKey(keys, name, email, passphrase)
	if err != nil {
		return fmt.Errorf("could not encode PGP secret key: %w", err)
	}
	publicBytes, err := encodeArmoredPublicKey(keys, name, email)
	if err != nil {
		return fmt.Errorf("could not encode PGP public key: %w", err)
	}

	// Write the secret key to --output when set, otherwise to stdout.
	if err := writeSecretKey(output, secretBytes); err != nil {
		return err
	}

	// Always print the public key so it can be shared on its own.
	if _, err := os.Stdout.Write(publicBytes); err != nil {
		return fmt.Errorf("could not write PGP public key: %w", err)
	}
	return nil
}

// writeSecretKey writes the armored OpenPGP secret key to path (0600) when set
// and to stdout otherwise. The matching public key is printed separately by
// runWithOptions.
func writeSecretKey(path string, secretBytes []byte) error {
	if path == "" {
		if _, err := os.Stdout.Write(secretBytes); err != nil {
			return fmt.Errorf("could not write PGP secret key: %w", err)
		}
		return nil
	}

	if err := os.WriteFile(path, secretBytes, secretKeyFileMode); err != nil {
		return fmt.Errorf("could not write PGP secret key to %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "PGP secret key written to: %s\n", path)
	fmt.Fprintf(os.Stderr, "Import the secret key with: gpg --import %s\n", path)
	return nil
}

// readOutputPassphrase is replaced in tests.
var readOutputPassphrase = defaultReadOutputPassphrase

func defaultReadOutputPassphrase(reusePassphrase bool, sourcePass []byte) ([]byte, error) {
	if reusePassphrase {
		if len(sourcePass) == 0 {
			return nil, errors.New("--reuse-passphrase requires the source key to be password-protected")
		}
		fmt.Fprintln(os.Stderr, "Reusing source key passphrase for the PGP key.")
		return sourcePass, nil
	}

	fmt.Fprint(os.Stderr, "Enter a passphrase for the PGP key (cannot be empty): ")
	pass, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase for PGP key cannot be empty")
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	confirm, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase confirmation: %w", err)
	}
	if !bytes.Equal(pass, confirm) {
		return nil, errors.New("passphrases do not match")
	}
	return pass, nil
}

func readPassword() ([]byte, error) {
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	return pass, nil
}

func encodeArmoredPrivateKey(keys *derive.PGPKeys, name, email string, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase for PGP key cannot be empty")
	}
	entity, err := buildEntity(keys, name, email)
	if err != nil {
		return nil, err
	}

	// Encrypt all private key material with the user's passphrase before
	// serializing. SerializePrivateWithoutSigning is used afterwards to avoid
	// attempting to sign with the now-encrypted keys.
	if err := entity.EncryptPrivateKeys(passphrase, nil); err != nil {
		return nil, fmt.Errorf("could not encrypt PGP private keys: %w", err)
	}
	return armorEntity(openpgp.PrivateKeyType, func(w io.Writer) error {
		return entity.SerializePrivateWithoutSigning(w, nil)
	})
}

func encodeArmoredPublicKey(keys *derive.PGPKeys, name, email string) ([]byte, error) {
	entity, err := buildEntity(keys, name, email)
	if err != nil {
		return nil, err
	}
	// Entity.Serialize emits only public key material; the secret packets are
	// never written.
	return armorEntity(openpgp.PublicKeyType, entity.Serialize)
}

// buildEntity constructs the OpenPGP entity from derived RSA key material: a
// primary [SC] key, a positive-certification self-signature binding the UID,
// and an [E] encryption subkey. The private packets are returned in the clear;
// callers either encrypt them for secret-key output or serialize only the
// public half.
func buildEntity(keys *derive.PGPKeys, name, email string) (*openpgp.Entity, error) {
	if keys == nil || keys.PrimaryKey == nil || keys.EncryptSubkey == nil {
		return nil, errors.New("PGP key material is incomplete")
	}

	primaryPrivPkt := packet.NewRSAPrivateKey(keys.CreationTime, keys.PrimaryKey)
	entity := &openpgp.Entity{
		PrimaryKey: &primaryPrivPkt.PublicKey,
		PrivateKey: primaryPrivPkt,
		Identities: make(map[string]*openpgp.Identity),
		Subkeys:    []openpgp.Subkey{},
		Signatures: []*packet.Signature{},
	}

	uid := packet.NewUserId(name, "", email)
	if uid == nil {
		return nil, errors.New("invalid PGP UID: name or email contains forbidden characters")
	}
	isPrimary := true
	uidSig := &packet.Signature{
		Version:           primaryPrivPkt.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        primaryPrivPkt.PubKeyAlgo,
		Hash:              crypto.SHA256,
		CreationTime:      keys.CreationTime,
		IssuerKeyId:       &primaryPrivPkt.KeyId,
		IssuerFingerprint: primaryPrivPkt.Fingerprint,
		FlagsValid:        true,
		FlagSign:          true,
		FlagCertify:       true,
		IsPrimaryId:       &isPrimary,
	}
	if err := uidSig.SignUserId(uid.Id, &primaryPrivPkt.PublicKey, primaryPrivPkt, nil); err != nil {
		return nil, fmt.Errorf("could not self-sign PGP UID: %w", err)
	}
	entity.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Id,
		UserId:        uid,
		SelfSignature: uidSig,
		Signatures:    []*packet.Signature{uidSig},
	}

	encryptPrivPkt := packet.NewRSAPrivateKey(keys.CreationTime, keys.EncryptSubkey)
	encryptPrivPkt.IsSubkey = true
	subkeySig := &packet.Signature{
		Version:                   primaryPrivPkt.Version,
		SigType:                   packet.SigTypeSubkeyBinding,
		PubKeyAlgo:                primaryPrivPkt.PubKeyAlgo,
		Hash:                      crypto.SHA256,
		CreationTime:              keys.CreationTime,
		IssuerKeyId:               &primaryPrivPkt.KeyId,
		IssuerFingerprint:         primaryPrivPkt.Fingerprint,
		FlagsValid:                true,
		FlagEncryptStorage:        true,
		FlagEncryptCommunications: true,
	}
	if err := subkeySig.SignKey(&encryptPrivPkt.PublicKey, primaryPrivPkt, nil); err != nil {
		return nil, fmt.Errorf("could not bind PGP encryption subkey: %w", err)
	}
	entity.Subkeys = append(entity.Subkeys, openpgp.Subkey{
		PublicKey:  &encryptPrivPkt.PublicKey,
		PrivateKey: encryptPrivPkt,
		Sig:        subkeySig,
	})

	return entity, nil
}

// armorEntity ASCII-armors the entity using the given armor type. serialize is
// called with the armor writer; the differing Entity serialization methods are
// wrapped by the caller.
func armorEntity(armorType string, serialize func(io.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	armorWriter, err := armor.Encode(&buf, armorType, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create PGP armor writer: %w", err)
	}
	if err := serialize(armorWriter); err != nil {
		return nil, fmt.Errorf("could not serialize PGP key: %w", err)
	}
	if err := armorWriter.Close(); err != nil {
		return nil, fmt.Errorf("could not finalize PGP armor: %w", err)
	}
	return buf.Bytes(), nil
}
