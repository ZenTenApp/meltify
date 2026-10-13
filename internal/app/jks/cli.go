// Package jks provides the meltify-jks CLI executable logic.
package jks

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	binaryName   = "meltify-jks"
	keystoreMode = 0o600
)

// Execute runs the meltify-jks CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount      string
		alias           string
		output          string
		dn              string
		bits            int
		validity        int
		reusePassphrase bool
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic Java KeyStore (.jks) from an Ed25519 OpenSSH key",
		Long: `meltify-jks derives a deterministic RSA private key and self-signed X.509
certificate from an Ed25519 OpenSSH private key, then writes a password-protected
Java KeyStore (.jks) file suitable for Android app signing.

The keystore is written to --output (0600). The stdout report lists the CI/CD
secrets (keystore base64, alias, store password, key password) so they can be
pasted into a signing pipeline.

The OpenSSH private key must be password-protected; meltify-jks prompts for that
passphrase. The keystore is always password-protected: enter a new passphrase, or
pass --reuse-passphrase to reuse the SSH key passphrase. Use --subaccount to
derive a deterministic subaccount key first.`,
		Example: `  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --dn "CN=Zenten, OU=Mobile, O=ZenTen"
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --bits 2048 --validity 10000
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --reuse-passphrase`,
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
			return runWithOptions(keyPath, subaccount, alias, output, dn, bits, validity, reusePassphrase, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&alias, "alias", "", "Keystore entry alias, e.g. zenten")
	rootCmd.Flags().StringVar(&output, "output", "", "Write the Java KeyStore (.jks) to this path (0600)")
	rootCmd.Flags().StringVar(&dn, "dn", "", `Certificate distinguished name, e.g. "CN=Zenten, OU=Mobile" (default: CN=<alias>)`)
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultRSABits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.Flags().IntVar(&validity, "validity", derive.DefaultJKSValidityDays, "Self-signed certificate validity in days")
	rootCmd.Flags().BoolVar(&reusePassphrase, "reuse-passphrase", false, "Reuse the source SSH key passphrase to protect the keystore; requires a password-protected source key")
	_ = rootCmd.MarkFlagRequired("alias")
	_ = rootCmd.MarkFlagRequired("output")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, alias, output, dn string, bits, validity int, reusePassphrase bool, stdin io.Reader) error {
	if err := derive.ValidRSABits(bits); err != nil {
		return fmt.Errorf("invalid --bits: %w", err)
	}
	if validity < 1 {
		return fmt.Errorf("invalid --validity: must be at least 1 day, got %d", validity)
	}
	if output == "" {
		return errors.New("--output is required")
	}

	var parsedDN pkix.Name
	if dn != "" {
		name, err := derive.ParseJKSDistinguishedName(dn)
		if err != nil {
			return fmt.Errorf("invalid --dn: %w", err)
		}
		parsedDN = name
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
		return fmt.Errorf("could not read JKS passphrase: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for JKS alias %q (this may take a moment)...\n", bits, alias)

	pair, err := derive.JKS(material.Key, alias, bits, validity, parsedDN)
	if err != nil {
		return fmt.Errorf("could not derive JKS keypair: %w", err)
	}

	jksBytes, err := derive.EncodeJKS(pair, passphrase)
	if err != nil {
		return fmt.Errorf("could not encode JKS keystore: %w", err)
	}

	if err := os.WriteFile(output, jksBytes, keystoreMode); err != nil {
		return fmt.Errorf("could not write JKS keystore to %s: %w", output, err)
	}

	fmt.Fprintf(os.Stderr, "JKS keystore written to: %s\n", output)
	fmt.Fprintf(os.Stderr, "Verify with: keytool -list -keystore %s -alias %s\n", output, alias)

	printSigningSecrets(output, alias, string(passphrase), string(passphrase), jksBytes)
	return nil
}

// readOutputPassphrase is replaced in tests.
var readOutputPassphrase = defaultReadOutputPassphrase

func defaultReadOutputPassphrase(reusePassphrase bool, sourcePass []byte) ([]byte, error) {
	if reusePassphrase {
		if len(sourcePass) == 0 {
			return nil, errors.New("--reuse-passphrase requires the source key to be password-protected")
		}
		fmt.Fprintln(os.Stderr, "Reusing source key passphrase for the JKS keystore.")
		return sourcePass, nil
	}

	fmt.Fprint(os.Stderr, "Enter a passphrase for the JKS keystore (cannot be empty): ")
	pass, err := readPassword()
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, errors.New("passphrase for JKS keystore cannot be empty")
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

func printSigningSecrets(keystorePath, alias, storePassword, keyPassword string, jksBytes []byte) {
	jksBase64 := base64.StdEncoding.EncodeToString(jksBytes)

	out := termout.New()
	out.Section("Android signing secrets")
	out.Blank()
	out.NamedSecret(
		"ANDROID_KEYSTORE_BASE64",
		jksBase64,
		"is the JKS file — base64-encoded contents of "+keystorePath,
		true,
	)
	out.NamedSecret(
		"ANDROID_KEY_ALIAS",
		alias,
		"chosen when you created the keystore — set via --alias; verify with keytool -list -keystore "+keystorePath,
		false,
	)
	out.NamedSecret(
		"ANDROID_STORE_PASSWORD",
		storePassword,
		"password you set when creating the keystore — required to open the file; cannot be extracted from the JKS",
		true,
	)
	out.NamedSecret(
		"ANDROID_KEY_PASSWORD",
		keyPassword,
		"password for the key entry inside the keystore — set at creation; for meltify-jks this is the same as the store password",
		true,
	)
}
