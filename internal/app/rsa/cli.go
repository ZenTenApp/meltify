// Package rsa provides the meltify-rsa CLI executable logic.
package rsa

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	binaryName         = "meltify-rsa"
	derivedKeyFileMode = 0o600
)

// Execute runs the meltify-rsa CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount        string
		output            string
		bits              int
		opensslCompatible bool
		reusePassphrase   bool
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic RSA private key from an Ed25519 OpenSSH key",
		Long: `meltify-rsa derives a deterministic RSA private key from an Ed25519 OpenSSH private key.

By default it prints an OpenSSH PEM private key. Pass --openssl-compatible to
emit an encrypted PKCS#8 PEM file instead (BEGIN ENCRYPTED PRIVATE KEY), readable
by openssl pkey -check. Pass --output <path> to write the key to a file (0600)
instead of stdout.

The OpenSSH private key must be password-protected; meltify-rsa prompts for that
passphrase. The derived RSA secret is always passphrase-protected: enter a new
passphrase, or pass --reuse-passphrase to reuse the SSH key passphrase. Use
--subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-rsa ~/.ssh/id_ed25519
  meltify-rsa ~/.ssh/id_ed25519 --output ~/.ssh/id_rsa_derived
  meltify-rsa ~/.ssh/id_ed25519 --openssl-compatible --output key.pem
  cat ~/.ssh/id_ed25519 | meltify-rsa
  meltify-rsa ~/.ssh/id_ed25519 --subaccount subaccount-label
  meltify-rsa ~/.ssh/id_ed25519 --reuse-passphrase --bits 2048`,
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
			return runWithOptions(keyPath, subaccount, output, bits, opensslCompatible, reusePassphrase, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&output, "output", "", "Write the derived RSA private key to this path (0600)")
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultRSABits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.Flags().BoolVar(&opensslCompatible, "openssl-compatible", false, "Write an encrypted PKCS#8 PEM file instead of OpenSSH format")
	rootCmd.Flags().BoolVar(&reusePassphrase, "reuse-passphrase", false, "Reuse the source SSH key passphrase to protect the derived key; requires a password-protected source key")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, output string, bits int, opensslCompatible, reusePassphrase bool, stdin io.Reader) error {
	if err := derive.ValidRSABits(bits); err != nil {
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
		return fmt.Errorf("could not read RSA passphrase: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA key (this may take a moment)...\n", bits)

	rsaKey, err := derive.RSA(material.Key, bits)
	if err != nil {
		return fmt.Errorf("could not derive RSA key: %w", err)
	}

	var pemBytes []byte
	if opensslCompatible {
		pemBytes, err = encodePKCS8(rsaKey, passphrase)
	} else {
		pemBytes, err = encodeOpenSSH(rsaKey, passphrase)
	}
	if err != nil {
		return fmt.Errorf("could not encode RSA key: %w", err)
	}

	if err := writeOutput(output, pemBytes); err != nil {
		return err
	}
	return nil
}

// readOutputPassphrase is replaced in tests.
var readOutputPassphrase = defaultReadOutputPassphrase

func defaultReadOutputPassphrase(reusePassphrase bool, sourcePass []byte) ([]byte, error) {
	if reusePassphrase {
		if len(sourcePass) == 0 {
			return nil, errors.New("--reuse-passphrase requires the source key to be password-protected")
		}
		fmt.Fprintln(os.Stderr, "Reusing source key passphrase for the derived key.")
		return sourcePass, nil
	}

	fmt.Fprint(os.Stderr, "Enter a passphrase for the derived key (cannot be empty): ")
	pass, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase for derived key cannot be empty")
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

func encodeOpenSSH(key *rsa.PrivateKey, passphrase []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("RSA key material is incomplete")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase for derived key cannot be empty")
	}

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", passphrase)
	if err != nil {
		return nil, fmt.Errorf("could not marshal derived key: %w", err)
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func encodePKCS8(key *rsa.PrivateKey, passphrase []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("RSA key material is incomplete")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("passphrase for derived key cannot be empty")
	}

	der, err := pkcs8.MarshalPrivateKey(key, passphrase, nil)
	if err != nil {
		return nil, fmt.Errorf("could not marshal derived key to PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: der,
	}), nil
}

func writeOutput(path string, pemBytes []byte) error {
	if path == "" {
		if _, err := os.Stdout.Write(pemBytes); err != nil {
			return fmt.Errorf("could not write RSA key: %w", err)
		}
		return nil
	}

	if err := os.WriteFile(path, pemBytes, derivedKeyFileMode); err != nil {
		return fmt.Errorf("could not write derived key to %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "Derived key written to: %s\n", path)
	return nil
}
