// Package bitchat provides the meltify-bitchat CLI executable logic.
//
// BitChat (iOS/Android) generates four independent random long-term secrets and
// has no import path, so the mapping meltify-bitchat implements is meltify's
// own, not a BitChat interoperability guarantee. See docs/meltify-bitchat.md.
package bitchat

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
)

const binaryName = "meltify-bitchat"

// Execute runs the meltify-bitchat CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic BitChat identity from an Ed25519 OpenSSH key",
		Long: `meltify-bitchat derives a deterministic BitChat identity from an Ed25519
OpenSSH private key.

BitChat stores four independent long-term secrets plus a user-chosen nickname:

  noise static key   X25519  mesh peer ID, fingerprint, Noise XX, courier seals
  signing key        Ed25519 announces, packets, vouches
  Nostr key          secp256k1 nsec / npub, relay DMs, location account
  device seed        32 bytes, per-geohash / bridge Nostr identities
  nickname           chosen by the user, not derived

Native BitChat (iOS/Android) has no import path, so this output cannot be loaded
there. The labels are meltify-native and the Nostr slice is the same NIP-06 nsec
meltify-info already prints, so one meltify identity keeps one nsec.

The OpenSSH private key must be password-protected; meltify-bitchat prompts for
that passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-bitchat ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-bitchat
  meltify-bitchat ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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

	keys, err := derive.BitChat(material.Key)
	if err != nil {
		return fmt.Errorf("could not derive BitChat identity: %w", err)
	}
	return printReport(keys)
}

// printReport renders every BitChat secret and the derived public material in
// the meltify block layout: secrets first, then public values, then the compact
// bitchat:<peer-id> line.
func printReport(keys *derive.BitChatKeys) error {
	if keys == nil {
		return errors.New("BitChat key material is incomplete")
	}
	if keys.Nostr == nil {
		return errors.New("BitChat identity is missing its Nostr slice")
	}

	out := termout.New()
	out.Blank()
	out.Block("NOISE STATIC (X25519)", hex.EncodeToString(keys.NoisePrivateKey), true)
	out.BlankPair()
	out.Block("ED25519 SIGNING SEED", hex.EncodeToString(keys.SigningSeed), true)
	out.BlankPair()
	out.Block("DEVICE SEED (GEOHASH HMAC)", hex.EncodeToString(keys.DeviceSeed), true)
	out.BlankPair()
	out.RawBorderBlock("----- nSecKey / hexSecKey -----", []termout.BlockLine{
		{Text: keys.Nostr.Nsec, Sensitive: true},
		{Text: keys.Nostr.PrivKeyHex, Sensitive: true},
	})
	out.BlankPair()
	out.Block("PEER ID", keys.PeerIDHex(), false)
	out.BlankPair()
	out.Block("NOISE FINGERPRINT", hex.EncodeToString(keys.NoiseFingerprint), false)
	out.BlankPair()
	out.Block("NOISE PUBLIC KEY", hex.EncodeToString(keys.NoisePublicKey), false)
	out.BlankPair()
	out.Block("ED25519 SIGNING PUBLIC KEY", hex.EncodeToString(keys.SigningPublicKey), false)
	out.BlankPair()
	out.RawBorderBlock("----- nPubKey / hexPubKey -----", []termout.BlockLine{
		{Text: keys.Nostr.Npub},
		{Text: keys.Nostr.PubKeyHex},
	})
	out.BlankPair()
	out.Value("bitchat:" + keys.PeerIDHex())
	out.Blank()
	return nil
}
