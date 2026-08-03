// Package meltify provides the main meltify CLI application.
package meltify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/ZenTenApp/seedify"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
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
		Short: "Export compact Nostr/SSH/MELT seed material from an Ed25519 OpenSSH key",
		Long: `meltify prints a compact, colored export from an Ed25519 OpenSSH private key:

- OpenSSH public key fingerprint
- OpenSSH public key with derived npub comment
- Nostr npub / hex public key
- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr nsec / hex secret key

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
	return printOutput(material.Key, material.PrivateKeyPEM)
}

func printOutput(key *ed25519.PrivateKey, privateKeyPEM []byte) error {
	sshPubKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to encode SSH public key: %w", err)
	}

	mnemonic24, err := seedify.ToMnemonicWithLength(key, 24, "", false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys: %w", err)
	}

	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return errors.New("failed to decode OpenSSH private key PEM block")
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	publicKeyLine := "ssh-ed25519 " + pubB64 + " " + nostrKeys.Npub
	privB64 := base64.StdEncoding.EncodeToString(privateKeyBlock.Bytes)
	seedHex := hex.EncodeToString(key.Seed())

	out := termout.New()
	out.Blank()
	out.Block("OPENSSH FINGERPRINT", ssh.FingerprintSHA256(sshPubKey), false)
	out.BlankPair()
	out.Block("OPENSSH PUBLIC KEY", publicKeyLine, false)
	out.BlankPair()
	out.RawBorderBlock("----- nPubKey / hexPubKey -----", []termout.BlockLine{
		{Text: nostrKeys.Npub},
		{Text: nostrKeys.PubKeyHex},
	})
	out.BlankPair()
	out.Block("OPENSSH PRIVATE KEY", privB64, true)
	out.BlankPair()
	out.Block("ED25519 SEED", seedHex, true)
	out.BlankPair()
	out.DoubleDelimitedBlock("24-WORD SEED PHRASE (charmbracelet/MELT)", mnemonic24, true)
	out.BlankPair()
	out.RawBorderBlock("----- nSecKey / hexSecKey -----", []termout.BlockLine{
		{Text: nostrKeys.Nsec, Sensitive: true},
		{Text: nostrKeys.PrivKeyHex, Sensitive: true},
	})
	out.BlankPair()

	return nil
}
