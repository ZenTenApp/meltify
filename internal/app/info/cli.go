// Package info provides the meltify-info CLI executable logic.
//
// meltify-info restores the original meltify identity export: a compact,
// colored report derived from a single Ed25519 OpenSSH private key.
package info

import (
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

// walletAddresses are the coin addresses deterministically derived from the
// 24-word MELT/BIP39 phrase (standard HD paths from the same BIP39 seed used
// for the Nostr keys).
type walletAddresses struct {
	Bitcoin  string // bc1q... (BIP84 m/84'/0'/0'/0/0, native segwit)
	Ethereum string // 0x... (BIP44 m/44'/60'/0'/0/0)
	Solana   string // Base58 (SLIP-0010 m/44'/501'/0'/0')
	Tron     string // T... (BIP44 m/44'/195'/0'/0/0)
}

// deriveWalletAddresses derives the four coin addresses from the given BIP39 mnemonic.
func deriveWalletAddresses(mnemonic string) (walletAddresses, error) {
	var (
		w   walletAddresses
		err error
	)
	if w.Bitcoin, err = seedify.DeriveBitcoinAddressNativeSegwit(mnemonic, ""); err != nil {
		return w, fmt.Errorf("could not derive bitcoin address: %w", err)
	}
	if w.Ethereum, err = seedify.DeriveEthereumAddress(mnemonic, ""); err != nil {
		return w, fmt.Errorf("could not derive ethereum address: %w", err)
	}
	if w.Solana, err = seedify.DeriveSolanaAddress(mnemonic, ""); err != nil {
		return w, fmt.Errorf("could not derive solana address: %w", err)
	}
	if w.Tron, err = seedify.DeriveTronAddress(mnemonic, ""); err != nil {
		return w, fmt.Errorf("could not derive tron address: %w", err)
	}
	return w, nil
}

// ExecuteInfo runs the meltify-info CLI.
func ExecuteInfo(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string

	rootCmd := &cobra.Command{
		Use:   "meltify-info [key-path]",
		Short: "Export a compact identity report (SSH, Nostr, MELT) from an Ed25519 OpenSSH key",
		Long: `meltify-info prints a compact, colored export from an Ed25519 OpenSSH private key:

- OpenSSH public key fingerprint
- OpenSSH public key with derived npub comment
- Nostr npub / hex public key
- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr nsec / hex secret key
- wallet addresses: bitcoin (bc1), ethereum, solana, tron

All forms are derived from the same master seed, so the SSH key, raw seed, and
MELT phrase are the same secret in different encodings; the Nostr keys and
wallet addresses are deterministically derived from it. Encrypted keys prompt
for the existing SSH key passphrase. Use --subaccount to report a
deterministic subaccount key.`,
		Example: `  meltify-info ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-info
  meltify-info ~/.ssh/id_ed25519 --subaccount subaccount-label`,
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
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, "meltify-info"))
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
	return printReport(material)
}

// printReport renders the full identity export from the unlocked key material.
func printReport(material *sshkey.Material) error {
	sshPubKey, err := ssh.NewPublicKey(material.Key.Public())
	if err != nil {
		return fmt.Errorf("failed to encode SSH public key: %w", err)
	}

	mnemonic24, err := seedify.ToMnemonicWithLength(material.Key, 24, "", false, 0) //nolint:mnd
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	nostrKeys, err := seedify.DeriveNostrKeysWithHex(mnemonic24, "")
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys: %w", err)
	}

	privateKeyBlock, _ := pem.Decode(material.PrivateKeyPEM)
	if privateKeyBlock == nil {
		return errors.New("failed to decode OpenSSH private key PEM block")
	}

	wallets, err := deriveWalletAddresses(mnemonic24)
	if err != nil {
		return err
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	publicKeyLine := "ssh-ed25519 " + pubB64 + " " + nostrKeys.Npub
	privB64 := base64.StdEncoding.EncodeToString(privateKeyBlock.Bytes)
	seedHex := hex.EncodeToString(material.Key.Seed())

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
	out.Blank()

	// Wallet addresses as seedify-style [section] headers (matching seedify's
	// "<coin> address from 24 word seed" layout).
	out.Section("bitcoin addresses from 24 word seed")
	out.Blank()
	out.Field(wallets.Bitcoin, "native segwit P2WPKH - BIP84 m/84'/0'/0'/0/0")
	out.Blank()
	out.AddressSection("ethereum address from 24 word seed", wallets.Ethereum)
	out.AddressSection("solana address from 24 word seed", wallets.Solana)
	out.AddressSection("tron address from 24 word seed", wallets.Tron)

	out.Blank()
	out.RawBorderBlock("----- nSecKey / hexSecKey -----", []termout.BlockLine{
		{Text: nostrKeys.Nsec, Sensitive: true},
		{Text: nostrKeys.PrivKeyHex, Sensitive: true},
	})
	out.BlankPair()
	return nil
}
