// Package wireguard provides the meltify-wireguard CLI executable logic.
package wireguard

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
)

const binaryName = "meltify-wireguard"

// Execute runs the meltify-wireguard CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic WireGuard static keypair from an Ed25519 OpenSSH key",
		Long: `meltify-wireguard derives a deterministic WireGuard static keypair from an
Ed25519 OpenSSH private key.

It prints the private and public keys in the base64 format used by
'wg genkey' / 'wg pubkey', ready to paste into a WireGuard [Interface] or
[Peer] section.

The OpenSSH private key must be password-protected; meltify-wireguard prompts
for that passphrase. Use --subaccount to derive a deterministic subaccount key
first.`,
		Example: `  meltify-wireguard ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-wireguard
  meltify-wireguard ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
			return runWithOptions(keyPath, subaccount, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount string, stdin io.Reader) error {
	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}

	keys, err := derive.WireGuard(material.Key)
	if err != nil {
		return fmt.Errorf("could not derive WireGuard keys: %w", err)
	}

	return printKeyMaterial(keys)
}

func printKeyMaterial(keys *derive.WireGuardKeys) error {
	if keys == nil {
		return errors.New("WireGuard key material is incomplete")
	}
	if _, printErr := fmt.Fprintf(os.Stdout, "PrivateKey = %s\n", keys.PrivateKey); printErr != nil {
		return fmt.Errorf("could not print WireGuard private key: %w", printErr)
	}
	if _, printErr := fmt.Fprintf(os.Stdout, "PublicKey  = %s\n", keys.PublicKey); printErr != nil {
		return fmt.Errorf("could not print WireGuard public key: %w", printErr)
	}
	return nil
}
