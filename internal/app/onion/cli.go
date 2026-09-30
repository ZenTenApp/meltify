// Package onion provides the meltify-onion CLI executable logic.
package onion

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
	binaryName = "meltify-onion"

	hiddenServiceDirMode  = 0o700
	hiddenServiceKeyMode  = 0o600
	hiddenServiceHostMode = 0o644

	secretKeyFile = "hs_ed25519_secret_key" //nolint:gosec // Tor HiddenServiceDir filename, not a credential.
	publicKeyFile = "hs_ed25519_public_key"
	hostnameFile  = "hostname"
)

// Execute runs the meltify-onion CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var (
		subaccount string
		output     string
	)

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a Tor v3 onion address from an Ed25519 OpenSSH key",
		Long: `meltify-onion derives a deterministic Tor v3 hidden service identity from an Ed25519 OpenSSH private key.

By default it prints the public .onion address. Pass --output <dir> to also write
a Tor HiddenServiceDir (hs_ed25519_secret_key, hs_ed25519_public_key, hostname).

The OpenSSH private key must be password-protected; meltify-onion prompts for that
passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-onion ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-onion
  meltify-onion ~/.ssh/id_ed25519 --output ./hidden_service
  meltify-onion ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
			return runWithOptions(keyPath, subaccount, output, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&output, "output", "", "Write Tor HiddenServiceDir files to this directory")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, output string, stdin io.Reader) error {
	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	keys, err := derive.Onion(material.Key)
	if err != nil {
		return fmt.Errorf("could not derive onion service keys: %w", err)
	}

	if output != "" {
		if err := writeHiddenServiceDir(output, keys); err != nil {
			return fmt.Errorf("could not write HiddenServiceDir: %w", err)
		}
	}

	fmt.Println(keys.Address)
	return nil
}

func writeHiddenServiceDir(dir string, keys *derive.OnionKeys) error {
	if keys == nil {
		return errors.New("onion key material is incomplete")
	}
	if err := os.MkdirAll(dir, hiddenServiceDirMode); err != nil {
		return fmt.Errorf("could not create output directory %s: %w", dir, err)
	}

	secretPath := filepath.Join(dir, secretKeyFile)
	publicPath := filepath.Join(dir, publicKeyFile)
	hostPath := filepath.Join(dir, hostnameFile)

	if err := os.WriteFile(secretPath, keys.PrivateKeyFile, hiddenServiceKeyMode); err != nil {
		return fmt.Errorf("could not write %s: %w", secretPath, err)
	}
	if err := os.WriteFile(publicPath, keys.PublicKeyFile, hiddenServiceKeyMode); err != nil {
		return fmt.Errorf("could not write %s: %w", publicPath, err)
	}
	if err := os.WriteFile(hostPath, keys.HostnameFile, hiddenServiceHostMode); err != nil {
		return fmt.Errorf("could not write %s: %w", hostPath, err)
	}
	return nil
}
