// Package brave provides the meltify-brave CLI application.
package brave

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/ZenTenApp/seedify"
	"github.com/spf13/cobra"
)

const binaryName = "meltify-brave"

// Execute runs the meltify-brave CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a Brave Sync-compatible MELT seed phrase from an Ed25519 OpenSSH key",
		Long: `meltify-brave derives a deterministic 25-word seed phrase from an Ed25519 OpenSSH private key.

The output is the 24-word charmbracelet/MELT seed phrase plus Brave Sync's daily 25th word appended.
Encrypted keys prompt for the existing SSH key passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-brave ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-brave
  meltify-brave ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
	return printOutput(material.Key)
}

func printOutput(key *ed25519.PrivateKey) error {
	mnemonic24, err := seedify.ToMnemonicWithLength(key, 24, "", false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	braveWord, err := seedify.BraveSync25thWord()
	if err != nil {
		return fmt.Errorf("could not get Brave Sync word: %w", err)
	}

	out := termout.New()
	out.Blank()
	out.DoubleDelimitedBlock("25-WORD SEED PHRASE (charmbracelet/MELT + Brave Sync)", mnemonic24+" "+braveWord, true)
	return nil
}
