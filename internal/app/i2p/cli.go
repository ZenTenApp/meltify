// Package i2p provides the meltify-i2p CLI executable logic.
package i2p

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
	binaryName = "meltify-i2p"

	destinationDirMode = 0o700
	keysDatMode        = 0o600

	keysDatFile = "keys.dat"
)

// Execute runs the meltify-i2p CLI.
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
		Short: "Export a deterministic I2P destination from an Ed25519 OpenSSH key",
		Long: `meltify-i2p derives a deterministic I2P Destination (Ed25519 signing key +
X25519 encryption key) from an Ed25519 OpenSSH private key.

By default it prints the .b32.i2p address and the two private-key components.
Pass --output <dir> to write the i2pd keys.dat file (0600) instead, which is
what an I2P router reads:

  [yourservice]
  type = server
  keys = keys.dat

The OpenSSH private key must be password-protected; meltify-i2p prompts for that
passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-i2p ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-i2p
  meltify-i2p ~/.ssh/id_ed25519 --output ./i2p-keys
  meltify-i2p ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
	rootCmd.Flags().StringVar(&output, "output", "", "Write the i2pd keys.dat file into this directory instead of printing key material")
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

	keys, err := derive.I2P(material.Key)
	if err != nil {
		return fmt.Errorf("could not derive I2P destination keys: %w", err)
	}

	if output == "" {
		return printKeyMaterial(keys)
	}

	if err := writeKeysDat(output, keys); err != nil {
		return fmt.Errorf("could not write keys.dat: %w", err)
	}

	fmt.Fprintf(os.Stderr, "B32 address: %s\n", keys.B32Address)
	fmt.Fprintf(os.Stderr, "File written to: %s\n", filepath.Join(output, keysDatFile))
	return nil
}

func printKeyMaterial(keys *derive.I2PKeys) error {
	if keys == nil {
		return errors.New("I2P key material is incomplete")
	}
	if _, printErr := fmt.Fprintf(os.Stdout, "B32 Address  : %s\n", keys.B32Address); printErr != nil {
		return fmt.Errorf("could not print B32 address: %w", printErr)
	}
	if _, printErr := fmt.Fprintf(os.Stdout, "X25519 PrivKey (hex): %x\n", keys.X25519PrivKey); printErr != nil {
		return fmt.Errorf("could not print X25519 private key: %w", printErr)
	}
	if _, printErr := fmt.Fprintf(os.Stdout, "Ed25519 Seed  (hex): %x\n", keys.Ed25519Seed); printErr != nil {
		return fmt.Errorf("could not print Ed25519 seed: %w", printErr)
	}
	return nil
}

func writeKeysDat(dir string, keys *derive.I2PKeys) error {
	if keys == nil {
		return errors.New("I2P key material is incomplete")
	}
	if err := os.MkdirAll(dir, destinationDirMode); err != nil {
		return fmt.Errorf("could not create output directory %s: %w", dir, err)
	}

	keysPath := filepath.Join(dir, keysDatFile)
	if err := os.WriteFile(keysPath, keys.PrivateKeyFile, keysDatMode); err != nil {
		return fmt.Errorf("could not write %s: %w", keysPath, err)
	}
	return nil
}
