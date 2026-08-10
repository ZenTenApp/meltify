// Package meltify provides the main meltify CLI application.
package meltify

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/spf13/cobra"
)

const binaryName = "meltify"

// Execute runs the meltify CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export raw Ed25519 seed material from an OpenSSH private key",
		Long: `meltify extracts the raw 32-byte Ed25519 seed from an OpenSSH private key and prints it as lowercase hex.

This output is secret key material. Do not pipe it to logs or untrusted commands.
Encrypted keys prompt for the existing SSH key passphrase.`,
		Example: `  meltify ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify
  meltify ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
	fmt.Println(hex.EncodeToString(material.Key.Seed()))
	return nil
}
