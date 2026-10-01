// Package dkim provides the meltify-dkim CLI executable logic.
package dkim

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
)

const (
	binaryName   = "meltify-dkim"
	dkimDirMode  = 0o700
	dkimPrivMode = 0o600
	dkimPubMode  = 0o644
)

// Execute runs the meltify-dkim CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount string
		output     string
		selector   string
		domain     string
		bits       int
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic DKIM key from an Ed25519 OpenSSH key",
		Long: `meltify-dkim derives a deterministic DKIM RSA keypair from an Ed25519 OpenSSH private key.

The private key is unencrypted PKCS#8 PEM (BEGIN PRIVATE KEY), the format OpenDKIM,
rspamd, Postfix, and Exim expect. It is not passphrase-protected; protect it with
file mode 0600. The public half is a DNS TXT record (v=DKIM1; k=rsa; p=...).

Pass --domain to write config/dkim/<domain>/<selector>.private and .public.
Pass --output <path> to write only the private key to that path. With neither,
the private key is printed to stdout and the DNS TXT record is printed to stderr.

The OpenSSH private key must be password-protected; meltify-dkim prompts for that
passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-dkim ~/.ssh/id_ed25519 --domain example.com
  meltify-dkim ~/.ssh/id_ed25519 --domain example.com --selector mail2026
  meltify-dkim ~/.ssh/id_ed25519 --output /etc/opendkim/keys/mail.private
  cat ~/.ssh/id_ed25519 | meltify-dkim --domain example.com
  meltify-dkim ~/.ssh/id_ed25519 --domain example.com --subaccount subaccount-label`,
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
			return runWithOptions(keyPath, subaccount, output, selector, domain, bits, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&selector, "selector", derive.DefaultDKIMSelector, "DKIM selector name for the DNS TXT record")
	rootCmd.Flags().StringVar(&domain, "domain", "", "Domain for the DNS TXT record; also writes config/dkim/<domain>/<selector>.private and .public when --output is omitted")
	rootCmd.Flags().StringVar(&output, "output", "", "Write the DKIM private key to this path (0600) instead of the config/dkim layout or stdout")
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultRSABits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, output, selector, domain string, bits int, stdin io.Reader) error {
	if err := derive.ValidRSABits(bits); err != nil {
		return fmt.Errorf("invalid --bits: %w", err)
	}
	if selector == "" {
		return errors.New("--selector is required")
	}

	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit RSA keypair for DKIM (this may take a moment)...\n", bits)

	keys, err := derive.DKIM(material.Key, selector, bits)
	if err != nil {
		return fmt.Errorf("could not derive DKIM keypair: %w", err)
	}

	switch {
	case output == "" && domain != "":
		if err := writeDKIMDir(domain, selector, keys); err != nil {
			return fmt.Errorf("could not write DKIM files: %w", err)
		}
	case output != "":
		if err := os.WriteFile(output, keys.PrivateKeyPEM, dkimPrivMode); err != nil {
			return fmt.Errorf("could not write DKIM private key to %s: %w", output, err)
		}
		fmt.Fprintf(os.Stderr, "DKIM private key written to: %s\n", output)
		printDNSInstructions(selector, domain, keys)
	default:
		if _, err := os.Stdout.Write(keys.PrivateKeyPEM); err != nil {
			return fmt.Errorf("could not write DKIM private key: %w", err)
		}
		printDNSInstructions(selector, domain, keys)
	}
	return nil
}

func writeDKIMDir(domain, selector string, keys *derive.DKIMKeys) error {
	if keys == nil {
		return errors.New("DKIM key material is incomplete")
	}
	if err := validPathComponent(selector, "selector"); err != nil {
		return err
	}
	if err := validPathComponent(domain, "domain"); err != nil {
		return err
	}

	dkimDir := filepath.Join("config", "dkim", domain)
	if err := os.MkdirAll(dkimDir, dkimDirMode); err != nil {
		return fmt.Errorf("could not create DKIM directory %s: %w", dkimDir, err)
	}

	privPath := filepath.Join(dkimDir, selector+".private")
	pubPath := filepath.Join(dkimDir, selector+".public")
	if err := os.WriteFile(privPath, keys.PrivateKeyPEM, dkimPrivMode); err != nil {
		return fmt.Errorf("could not write DKIM private key to %s: %w", privPath, err)
	}
	pubContent := []byte(keys.DNSTXTRecord + "\n")
	if err := os.WriteFile(pubPath, pubContent, dkimPubMode); err != nil { //nolint:gosec // DNS TXT record is public.
		return fmt.Errorf("could not write DKIM public key to %s: %w", pubPath, err)
	}

	fmt.Fprintf(os.Stderr, "DKIM private key written to: %s\n", privPath)
	fmt.Fprintf(os.Stderr, "DKIM public key written to:  %s\n", pubPath)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "DNS TXT record name: %s._domainkey.%s\n", selector, domain)
	fmt.Fprintf(os.Stderr, "DNS TXT record value is in: %s\n", pubPath)
	printTXTSplitNote()
	return nil
}

func printDNSInstructions(selector, domain string, keys *derive.DKIMKeys) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "DNS TXT record for DKIM:")
	if domain != "" {
		fmt.Fprintf(os.Stderr, "  Name:  %s._domainkey.%s\n", selector, domain)
	} else {
		fmt.Fprintf(os.Stderr, "  Name:  %s._domainkey.<your-domain>\n", selector)
	}
	fmt.Fprintf(os.Stderr, "  Value: %s\n", keys.DNSTXTRecord)
	printTXTSplitNote()
}

func printTXTSplitNote() {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Note: some DNS providers require TXT record values to be split into")
	fmt.Fprintln(os.Stderr, "      255-character chunks. Check your provider's documentation if")
	fmt.Fprintln(os.Stderr, "      the record is rejected. For a 4096-bit key the value is ~736")
	fmt.Fprintln(os.Stderr, "      characters; for 2048-bit it is ~392 characters.")
}

func validPathComponent(name, label string) error {
	if name == "" {
		return fmt.Errorf("DKIM %s is required", label)
	}
	if name != filepath.Base(name) || strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid DKIM %s %q", label, name)
	}
	return nil
}
