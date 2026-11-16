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
	"path/filepath"
	"strings"

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

// keystoreFormat is the keystore container meltify-jks writes.
type keystoreFormat int

const (
	// formatJKS writes a Java KeyStore (.jks), which supports separate store and
	// key passwords.
	formatJKS keystoreFormat = iota

	// formatPKCS12 writes a PKCS#12 keystore (.p12/.pfx), which has a single
	// password for the store and its key entry.
	formatPKCS12
)

// label is the human-readable name of the format.
func (f keystoreFormat) label() string {
	if f == formatPKCS12 {
		return "PKCS#12"
	}
	return "JKS"
}

// keytoolListCommand is the keytool invocation that lists the keystore entries.
func (f keystoreFormat) keytoolListCommand(path string) string {
	if f == formatPKCS12 {
		return "keytool -list -storetype PKCS12 -keystore " + path
	}
	return "keytool -list -keystore " + path
}

// formatForOutputPath infers the keystore format from the --output extension.
// PKCS#12 keystores are written for .p12, .pfx, and .pkcs12 paths; every other
// path yields a Java KeyStore.
func formatForOutputPath(path string) keystoreFormat {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p12", ".pfx", ".pkcs12":
		return formatPKCS12
	default:
		return formatJKS
	}
}

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
		storePassword   string
		keyPassword     string
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic Java KeyStore or PKCS#12 keystore from an Ed25519 OpenSSH key",
		Long: `meltify-jks derives a deterministic RSA private key and self-signed X.509
certificate from an Ed25519 OpenSSH private key, then writes a password-protected
keystore file suitable for Android app signing.

The keystore format follows the --output extension: .p12, .pfx, and .pkcs12
write a PKCS#12 keystore, and any other path writes a Java KeyStore (.jks). Both
formats are accepted by Android Gradle Plugin signing configs.

The keystore is written to --output (0600). The stdout report lists the CI/CD
secrets (keystore base64, alias, store password, key password) so they can be
pasted into a signing pipeline.

The OpenSSH private key must be password-protected; meltify-jks prompts for that
passphrase. The keystore is always password-protected: enter a new passphrase, or
pass --reuse-passphrase to reuse the SSH key passphrase. Alternatively, supply
--store-password. In a Java KeyStore the key entry uses the store password unless
--key-password is provided; PKCS#12 has a single password, so --key-password is
rejected there. Password flags may be visible in shell history and process
listings. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --dn "CN=Zenten, OU=Mobile, O=ZenTen"
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --bits 2048 --validity 10000
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.jks --reuse-passphrase
  meltify-jks ~/.ssh/id_ed25519 --alias zenten --output zenten-release.p12`,
		Version:      info.String(),
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("store-password") && storePassword == "" {
				return errors.New("--store-password cannot be empty")
			}
			if cmd.Flags().Changed("key-password") && keyPassword == "" {
				return errors.New("--key-password cannot be empty")
			}
			if cmd.Flags().Changed("key-password") && formatForOutputPath(output) == formatPKCS12 {
				return errors.New("--key-password is not supported for PKCS#12 keystores: PKCS#12 uses a single password for the keystore and its key entry")
			}
			if len(args) == 0 && stdin == os.Stdin {
				if fi, statErr := os.Stdin.Stat(); statErr == nil && (fi.Mode()&os.ModeNamedPipe) == 0 {
					return cmd.Help()
				}
			}

			keyPath := "-"
			if len(args) > 0 {
				keyPath = args[0]
			}
			return runWithOptions(keyPath, subaccount, alias, output, dn, bits, validity, reusePassphrase, storePassword, keyPassword, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&alias, "alias", "", "Keystore entry alias, e.g. zenten")
	rootCmd.Flags().StringVar(&output, "output", "", "Write the keystore to this path (0600); .p12/.pfx/.pkcs12 write PKCS#12, anything else writes a Java KeyStore")
	rootCmd.Flags().StringVar(&dn, "dn", "", `Certificate distinguished name, e.g. "CN=Zenten, OU=Mobile" (default: CN=<alias>)`)
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultRSABits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.Flags().IntVar(&validity, "validity", derive.DefaultJKSValidityDays, "Self-signed certificate validity in days")
	rootCmd.Flags().BoolVar(&reusePassphrase, "reuse-passphrase", false, "Reuse the source SSH key passphrase to protect the keystore; requires a password-protected source key")
	rootCmd.Flags().StringVar(&storePassword, "store-password", "", "Keystore password (default: prompt or --reuse-passphrase; visible in process arguments)")
	rootCmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key entry password for Java KeyStore output (default: store password; rejected for PKCS#12; visible in process arguments)")
	rootCmd.MarkFlagsMutuallyExclusive("store-password", "reuse-passphrase")
	_ = rootCmd.MarkFlagRequired("alias")
	_ = rootCmd.MarkFlagRequired("output")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, alias, output, dn string, bits, validity int, reusePassphrase bool, storePassword, keyPassword string, stdin io.Reader) error {
	format := formatForOutputPath(output)
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

	storePassword, keyPassword, err = resolvePasswords(storePassword, keyPassword, reusePassphrase, material.SourcePass)
	if err != nil {
		return fmt.Errorf("could not read keystore passphrase: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for %s alias %q (this may take a moment)...\n", bits, format.label(), alias)

	pair, err := derive.JKS(material.Key, alias, bits, validity, parsedDN)
	if err != nil {
		return fmt.Errorf("could not derive JKS keypair: %w", err)
	}

	keystoreBytes, err := encodeKeystore(pair, format, storePassword, keyPassword)
	if err != nil {
		return err
	}

	if err := os.WriteFile(output, keystoreBytes, keystoreMode); err != nil {
		return fmt.Errorf("could not write %s keystore to %s: %w", format.label(), output, err)
	}

	fmt.Fprintf(os.Stderr, "%s keystore written to: %s\n", format.label(), output)
	fmt.Fprintf(os.Stderr, "Verify with: %s -alias %s\n", format.keytoolListCommand(output), alias)

	printSigningSecrets(output, alias, storePassword, keyPassword, keystoreBytes, format)
	return nil
}

// encodeKeystore encodes the derived keypair in the requested format.
func encodeKeystore(pair *derive.JKSKeypair, format keystoreFormat, storePassword, keyPassword string) ([]byte, error) {
	if format == formatPKCS12 {
		pfxBytes, err := derive.EncodePKCS12(pair, []byte(storePassword))
		if err != nil {
			return nil, fmt.Errorf("could not encode PKCS#12 keystore: %w", err)
		}
		return pfxBytes, nil
	}

	jksBytes, err := derive.EncodeJKSWithPasswords(pair, []byte(storePassword), []byte(keyPassword))
	if err != nil {
		return nil, fmt.Errorf("could not encode JKS keystore: %w", err)
	}
	return jksBytes, nil
}

func resolvePasswords(storePassword, keyPassword string, reusePassphrase bool, sourcePass []byte) (string, string, error) {
	if storePassword == "" {
		passphrase, err := readOutputPassphrase(reusePassphrase, sourcePass)
		if err != nil {
			return "", "", err
		}
		storePassword = string(passphrase)
	}
	if keyPassword == "" {
		keyPassword = storePassword
	}
	return storePassword, keyPassword, nil
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

func printSigningSecrets(keystorePath, alias, storePassword, keyPassword string, keystoreBytes []byte, format keystoreFormat) {
	keystoreBase64 := base64.StdEncoding.EncodeToString(keystoreBytes)

	out := termout.New()
	out.Section("Android signing secrets")
	out.Blank()
	out.NamedSecret(
		"ANDROID_KEYSTORE_BASE64",
		keystoreBase64,
		"is the "+format.label()+" file — base64-encoded contents of "+keystorePath,
		true,
	)
	out.NamedSecret(
		"ANDROID_KEY_ALIAS",
		alias,
		"chosen when you created the keystore — set via --alias; verify with "+format.keytoolListCommand(keystorePath),
		false,
	)
	out.NamedSecret(
		"ANDROID_STORE_PASSWORD",
		storePassword,
		"password you set when creating the keystore — required to open the file; cannot be extracted from the "+format.label(),
		true,
	)
	out.NamedSecret(
		"ANDROID_KEY_PASSWORD",
		keyPassword,
		"password for the key entry inside the keystore — defaults to the store password unless set via --key-password",
		true,
	)
}
