// Package info provides the meltify-info CLI executable logic.
//
// meltify-info restores the original meltify identity export: a compact,
// colored report derived from a single Ed25519 OpenSSH private key.
package info

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ZenTenApp/meltify/internal/app/bchat"
	"github.com/ZenTenApp/meltify/internal/app/cryptonote"
	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

type labeledAddress struct {
	label string
	addr  string
}

// deriveWalletAddresses derives meltify-info chain addresses and the BChat
// chat ID. BIP39 chains use mnemonic; Monero and Beldex use the 25-word
// CryptoNote legacy phrase from key (same as meltify-monero / meltify-beldex).
// EVM aliases reuse the Ethereum 0x address. BChat is not a chain and is
// returned separately so the report can print it after the address list.
func deriveWalletAddresses(key *ed25519.PrivateKey, mnemonic string) ([]labeledAddress, string, error) {
	eth, err := derive.Ethereum(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive ethereum address: %w", err)
	}
	btc, err := derive.BitcoinNativeSegwit(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive bitcoin address: %w", err)
	}
	bch, err := derive.BitcoinCash(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive bitcoin cash address: %w", err)
	}
	sol, err := derive.Solana(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive solana address: %w", err)
	}
	trx, err := derive.Tron(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive tron address: %w", err)
	}
	ltc, err := derive.Litecoin(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive litecoin address: %w", err)
	}
	doge, err := derive.Dogecoin(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive dogecoin address: %w", err)
	}
	atom, err := derive.Cosmos(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive cosmos address: %w", err)
	}
	xrp, err := derive.Ripple(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive xrpl address: %w", err)
	}
	xlm, err := derive.Stellar(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive stellar address: %w", err)
	}
	sui, err := derive.Sui(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive sui address: %w", err)
	}
	tonAddr, err := derive.Ton(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive ton address: %w", err)
	}
	sp, err := derive.SilentPayment(mnemonic, "")
	if err != nil {
		return nil, "", fmt.Errorf("could not derive silent payment address: %w", err)
	}

	legacy, err := cryptonote.LegacyPhrase(key)
	if err != nil {
		return nil, "", fmt.Errorf("could not derive legacy CryptoNote seed: %w", err)
	}
	xmr, err := derive.MoneroFromLegacy(legacy, 0)
	if err != nil {
		return nil, "", fmt.Errorf("could not derive monero address: %w", err)
	}
	bdx, err := derive.BeldexFromLegacy(legacy, 0)
	if err != nil {
		return nil, "", fmt.Errorf("could not derive beldex address: %w", err)
	}
	chatID, err := bchat.DeriveChatID(cryptonote.LegacySeedBytes(key))
	if err != nil {
		return nil, "", fmt.Errorf("could not derive bchat identity: %w", err)
	}

	return []labeledAddress{
		{"arbitrum", eth},
		{"arc", eth},
		{"avalanche", eth},
		{"base", eth},
		{"beldex", bdx.PrimaryAddress},
		{"bitcoin", btc},
		{"bitcoincash", bch},
		{"bnbchain", eth},
		{"celo", eth},
		{"cosmos", atom},
		{"cronos", eth},
		{"dogecoin", doge},
		{"ethereum", eth},
		{"gnosis", eth},
		{"hyperevm", eth},
		{"litecoin", ltc},
		{"monad", eth},
		{"monero", xmr.PrimaryAddress},
		{"optimism", eth},
		{"plasma", eth},
		{"polygon", eth},
		{"silentpayment", sp},
		{"solana", sol},
		{"stablechain", eth},
		{"stellar", xlm},
		{"sui", sui},
		{"ton", tonAddr},
		{"tron", trx},
		{"worldchain", eth},
		{"xrpl", xrp},
	}, chatID, nil
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

- OpenSSH private key body
- raw Ed25519 seed
- 24-word charmbracelet/MELT seed phrase
- Nostr nsec / hex secret key
- OpenSSH public key fingerprint
- OpenSSH public key with derived npub comment
- Nostr npub / hex public key
- wallet addresses as label:address (EVM chains reuse the Ethereum 0x;
  TON is Wallet V4R2 UQ at m/44'/607'/0'; Monero and Beldex use the
  25-word CryptoNote legacy primary)
- BChat chat ID, printed after the chain list (not a crypto chain)

All forms are derived from the same master seed, so the SSH key, raw seed, and
MELT phrase are the same secret in different encodings; the Nostr keys and
BIP39 wallet addresses are deterministically derived from it. Encrypted keys prompt
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

	mnemonic24, err := derive.Mnemonic24(material.Key)
	if err != nil {
		return fmt.Errorf("could not generate 24-word MELT mnemonic: %w", err)
	}

	nostrKeys, err := derive.NostrKeysFromMnemonic(mnemonic24, "")
	if err != nil {
		return fmt.Errorf("could not derive Nostr keys: %w", err)
	}

	privateKeyBlock, _ := pem.Decode(material.PrivateKeyPEM)
	if privateKeyBlock == nil {
		return errors.New("failed to decode OpenSSH private key PEM block")
	}

	wallets, chatID, err := deriveWalletAddresses(material.Key, mnemonic24)
	if err != nil {
		return err
	}

	pubB64 := base64.StdEncoding.EncodeToString(sshPubKey.Marshal())
	publicKeyLine := "ssh-ed25519 " + pubB64 + " " + nostrKeys.Npub
	privB64 := base64.StdEncoding.EncodeToString(privateKeyBlock.Bytes)
	seedHex := hex.EncodeToString(material.Key.Seed())

	out := termout.New()
	out.Blank()
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
	out.Block("OPENSSH FINGERPRINT", ssh.FingerprintSHA256(sshPubKey), false)
	out.BlankPair()
	out.Block("OPENSSH PUBLIC KEY", publicKeyLine, false)
	out.BlankPair()
	out.RawBorderBlock("----- nPubKey / hexPubKey -----", []termout.BlockLine{
		{Text: nostrKeys.Npub},
		{Text: nostrKeys.PubKeyHex},
	})
	out.BlankPair()

	for _, w := range wallets {
		out.Value(w.label + ":" + w.addr)
	}
	out.Blank()
	out.Value("bchat:" + chatID)
	out.Blank()
	return nil
}
