// Package dnssec provides the meltify-dnssec CLI executable logic.
package dnssec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
)

const (
	binaryName = "meltify-dnssec"

	dnssecDirMode  = 0o700
	dnssecKeyMode  = 0o644
	dnssecPrivMode = 0o600
	dnssecDSMode   = 0o644
)

// Execute runs the meltify-dnssec CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount string
		output     string
		domain     string
		bits       int
		ksk        bool
		zsk        bool
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic DNSSEC RSASHA256 keypair from an Ed25519 OpenSSH key",
		Long: `meltify-dnssec derives a deterministic BIND-compatible DNSSEC keypair from an Ed25519 OpenSSH private key.

Only algorithm 8 (RSASHA256) is supported. The zone name, algorithm, KSK/ZSK role,
and RSA bit size are mixed into the derivation, so each zone and role gets a
cryptographically distinct key.

By default it prints the public DNSKEY and DS records to stdout. Pass
--output <dir> to write BIND files instead:
  K<zone>.+008+<keytag>.key      public DNSKEY RR (0644)
  K<zone>.+008+<keytag>.private  private key, BIND v1.3 format (0600)
  K<zone>.+008+<keytag>.ds       SHA-256 DS RR for the parent zone (0644)

The OpenSSH private key must be password-protected; meltify-dnssec prompts for
that passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-dnssec ~/.ssh/id_ed25519 --domain example.com
  meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --ksk --output ./dnssec-keys
  meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --zsk --output ./dnssec-keys
  cat ~/.ssh/id_ed25519 | meltify-dnssec --domain example.com
  meltify-dnssec ~/.ssh/id_ed25519 --domain example.com --subaccount subaccount-label`,
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
			return runWithOptions(keyPath, subaccount, output, domain, bits, ksk, zsk, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&domain, "domain", "", "Zone name for DNSSEC output, e.g. example.com (required)")
	rootCmd.Flags().IntVar(&bits, "bits", derive.DefaultRSABits, "RSA key size in bits (2048, 3072, or 4096)")
	rootCmd.Flags().BoolVar(&ksk, "ksk", false, "Generate a key-signing key with DNSKEY flags 257 (default)")
	rootCmd.Flags().BoolVar(&zsk, "zsk", false, "Generate a zone-signing key with DNSKEY flags 256")
	rootCmd.Flags().StringVar(&output, "output", "", "Write BIND .key/.private/.ds files into this directory instead of printing records")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, output, domain string, bits int, ksk, zsk bool, stdin io.Reader) error {
	if domain == "" {
		return errors.New("--domain is required")
	}
	if ksk && zsk {
		return errors.New("--ksk and --zsk are mutually exclusive")
	}
	if err := derive.ValidRSABits(bits); err != nil {
		return fmt.Errorf("invalid --bits: %w", err)
	}

	flags := derive.DNSSECKSKFlags
	if zsk {
		flags = derive.DNSSECZSKFlags
	}

	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Deriving %d-bit DNSSEC RSASHA256 keypair for %s (this may take a moment)...\n", bits, domain)

	pair, err := derive.DNSSEC(material.Key, domain, derive.DNSSECAlgorithmRSASHA256, flags, bits)
	if err != nil {
		return fmt.Errorf("could not derive DNSSEC keypair: %w", err)
	}

	if output != "" {
		if err := writeDNSSECDir(output, pair); err != nil {
			return fmt.Errorf("could not write DNSSEC files: %w", err)
		}
		fmt.Fprintln(os.Stderr)
	}

	fmt.Fprintln(os.Stderr, "DNSSEC records:")
	fmt.Fprintf(os.Stderr, "  DNSKEY: %s\n", pair.DNSKEYRecord)
	fmt.Fprintf(os.Stderr, "  DS:     %s\n", pair.DSRecord)
	fmt.Fprintf(os.Stderr, "  Key ID: %05d\n", pair.KeyTag)

	if output == "" {
		if _, printErr := fmt.Fprintln(os.Stdout, pair.DNSKEYRecord); printErr != nil {
			return fmt.Errorf("could not print DNSKEY record: %w", printErr)
		}
		if _, printErr := fmt.Fprintln(os.Stdout, pair.DSRecord); printErr != nil {
			return fmt.Errorf("could not print DS record: %w", printErr)
		}
	}

	return nil
}

func writeDNSSECDir(dir string, pair *derive.DNSSECKeypair) error {
	if pair == nil {
		return errors.New("DNSSEC key material is incomplete")
	}
	if err := os.MkdirAll(dir, dnssecDirMode); err != nil {
		return fmt.Errorf("could not create DNSSEC output directory %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, pair.FileBase+".key")
	privatePath := filepath.Join(dir, pair.FileBase+".private")
	dsPath := filepath.Join(dir, pair.FileBase+".ds")

	if err := os.WriteFile(keyPath, pair.KeyFile, dnssecKeyMode); err != nil {
		return fmt.Errorf("could not write DNSSEC public key to %s: %w", keyPath, err)
	}
	if err := os.WriteFile(privatePath, pair.PrivateKeyFile, dnssecPrivMode); err != nil {
		return fmt.Errorf("could not write DNSSEC private key to %s: %w", privatePath, err)
	}
	if err := os.WriteFile(dsPath, []byte(pair.DSRecord+"\n"), dnssecDSMode); err != nil {
		return fmt.Errorf("could not write DNSSEC DS record to %s: %w", dsPath, err)
	}

	fmt.Fprintf(os.Stderr, "DNSSEC public key written to:  %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "DNSSEC private key written to: %s\n", privatePath)
	fmt.Fprintf(os.Stderr, "DNSSEC DS record written to:   %s\n", dsPath)
	return nil
}
