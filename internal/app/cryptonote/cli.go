// Package cryptonote provides CLIs for CryptoNote-family meltify executables.
package cryptonote

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ZenTenApp/meltify/internal/app/bchat"
	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/derive"
	"github.com/ZenTenApp/meltify/internal/meltifyexec"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/spf13/cobra"
)

const defaultAddressCount = 9

// AddressSet contains a CryptoNote primary address and subaddresses.
type AddressSet struct {
	PrimaryAddress string
	Subaddresses   []string
}

// CoinConfig describes one CryptoNote-family executable.
type CoinConfig struct {
	BinaryName      string
	DisplayName     string
	Symbol          string
	SeedLabel       string
	AddressLabel    string
	DeriveAddresses func(seed string, count int) (AddressSet, error)
	// ExtraLabel and DeriveExtra render an additional identity block after the
	// seed. DeriveExtra receives the exact 32 bytes encoded by the printed
	// 25-word seed (for CryptoNote coins: the scReduced seed), so identities
	// derived from it match restoring the printed seed in the wallet. Empty
	// DeriveExtra disables the block.
	ExtraLabel  string
	DeriveExtra func(seed []byte) (string, error)
	// MergeCake makes the Monero CLI print the legacy section and the
	// Unstoppable/Cake section in one output, separated by a divider. Beldex
	// leaves this false and keeps the single-section layout.
	MergeCake bool
}

// BeldexConfig configures meltify-beldex.
var BeldexConfig = CoinConfig{
	BinaryName:   "meltify-beldex",
	DisplayName:  "Beldex",
	Symbol:       "BDX",
	SeedLabel:    "25-WORD BELDEX (BDX) SEED",
	AddressLabel: "BELDEX ADDRESSES FROM 25-WORD SEED",
	DeriveAddresses: func(seed string, count int) (AddressSet, error) {
		keys, err := derive.BeldexFromLegacy(seed, count)
		if err != nil {
			return AddressSet{}, fmt.Errorf("derive Beldex keys from legacy seed: %w", err)
		}
		return AddressSet{PrimaryAddress: keys.PrimaryAddress, Subaddresses: keys.Subaddresses}, nil
	},
	ExtraLabel: "BELDEX CHAT ID (BCHAT)",
	DeriveExtra: func(seed []byte) (string, error) {
		chatID, err := bchat.DeriveChatID(seed)
		if err != nil {
			return "", fmt.Errorf("derive Beldex chat id: %w", err)
		}
		return chatID, nil
	},
}

// MoneroConfig configures meltify-monero.
var MoneroConfig = CoinConfig{
	BinaryName:   "meltify-monero",
	DisplayName:  "Monero",
	Symbol:       "XMR",
	SeedLabel:    "25-WORD MONERO LEGACY SEED",
	AddressLabel: "MONERO ADDRESSES FROM 25-WORD LEGACY SEED",
	DeriveAddresses: func(seed string, count int) (AddressSet, error) {
		keys, err := derive.MoneroFromLegacy(seed, count)
		if err != nil {
			return AddressSet{}, fmt.Errorf("derive Monero keys from legacy seed: %w", err)
		}
		return AddressSet{PrimaryAddress: keys.PrimaryAddress, Subaddresses: keys.Subaddresses}, nil
	},
	MergeCake: true,
}

// ExecuteBeldex runs the meltify-beldex CLI.
func ExecuteBeldex(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	return Execute(args, stdin, info, BeldexConfig)
}

// ExecuteMonero runs the meltify-monero CLI.
func ExecuteMonero(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	return Execute(args, stdin, info, MoneroConfig)
}

// Execute runs a CryptoNote-family CLI.
func Execute(args []string, stdin io.Reader, info cliutil.VersionInfo, coin CoinConfig) error {
	cmd := newRootCommand(stdin, info, coin)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo, coin CoinConfig) *cobra.Command {
	var subaccount string

	long := fmt.Sprintf(`%[1]s derives a deterministic %[2]s seed and addresses from an Ed25519 OpenSSH private key.

The OpenSSH private key must be password-protected; %[1]s prompts for that passphrase. Use --subaccount to derive a deterministic subaccount key first.`, coin.BinaryName, coin.DisplayName)
	example := fmt.Sprintf(`  %[1]s ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | %[1]s
  %[1]s ~/.ssh/id_ed25519 --subaccount subaccount-label`, coin.BinaryName)

	rootCmd := &cobra.Command{
		Use:          coin.BinaryName + " [key-path]",
		Short:        fmt.Sprintf("Export %s seed and addresses from an Ed25519 OpenSSH key", coin.DisplayName),
		Long:         long,
		Example:      example,
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
			return runWithOptions(keyPath, subaccount, stdin, coin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, coin.BinaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount string, stdin io.Reader, coin CoinConfig) error {
	seed, err := meltifyexec.ExtractSeed(keyPath, subaccount, stdin)
	if err != nil {
		return fmt.Errorf("could not extract key material with meltify: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return printCoinOutput(&key, coin)
}

func cakePhraseFromMnemonic(mnemonic string) (string, error) {
	spend, err := derive.CakeSpendKey(mnemonic, "", 0)
	if err != nil {
		return "", fmt.Errorf("could not derive cake wallet spend key: %w", err)
	}
	phrase, err := LegacyPhraseFromBytes(spend)
	if err != nil {
		return "", fmt.Errorf("could not encode cake wallet 25-word seed: %w", err)
	}
	return phrase, nil
}

func printCoinOutput(key *ed25519.PrivateKey, coin CoinConfig) error {
	if coin.MergeCake {
		return printMergedCoinOutput(key, coin)
	}

	seed, err := legacySeedFromKey(key)
	if err != nil {
		return fmt.Errorf("failed to derive %s seed: %w", coin.DisplayName, err)
	}

	addresses, err := coin.DeriveAddresses(seed, defaultAddressCount)
	if err != nil {
		return fmt.Errorf("failed to derive %s addresses: %w", coin.DisplayName, err)
	}

	out := termout.New()
	out.Blank()
	out.DoubleDelimitedBlock(coin.SeedLabel, seed, true)
	if coin.DeriveExtra != nil {
		extra, extraErr := coin.DeriveExtra(legacySeedBytesFromKey(key))
		if extraErr != nil {
			return fmt.Errorf("failed to derive %s extra output: %w", coin.DisplayName, extraErr)
		}
		out.BlankPair()
		out.Block(coin.ExtraLabel, extra, false)
	}
	out.BlankPair()
	out.Block(strings.ToUpper(coin.DisplayName)+" PRIMARY ADDRESS", addresses.PrimaryAddress, false)
	if len(addresses.Subaddresses) > 0 {
		out.BlankPair()
		out.RawBorderBlock("----- "+coin.AddressLabel+" -----", subaddressLines(addresses.Subaddresses))
	}
	out.BlankPair()
	return nil
}

// Labels for the merged meltify-monero output. The trailing space on the
// Unstoppable label is intentional: the requested header renders it as
// `... "mnemonic" =====`.
const (
	moneroUnstoppableSeedLabel = `MONERO LEGACY SEED for Unstoppable Wallet - 24 word "mnemonic" `
	moneroCakeSeedLabel        = "MONERO LEGACY SEED for Cake/feather Wallet - 25 word"
	moneroMergedSeedEndLabel   = "MONERO LEGACY SEED"
)

// printMergedCoinOutput prints the legacy CryptoNote section and the
// Unstoppable/Cake section in one output, separated by an asterisk divider.
// It is used by meltify-monero only; meltify-beldex keeps the single-section
// layout.
func printMergedCoinOutput(key *ed25519.PrivateKey, coin CoinConfig) error {
	legacySeed, err := legacySeedFromKey(key)
	if err != nil {
		return fmt.Errorf("failed to derive %s seed: %w", coin.DisplayName, err)
	}
	legacyAddresses, err := coin.DeriveAddresses(legacySeed, defaultAddressCount)
	if err != nil {
		return fmt.Errorf("failed to derive %s addresses: %w", coin.DisplayName, err)
	}

	mnemonic24, err := derive.Mnemonic24(key)
	if err != nil {
		return fmt.Errorf("could not generate 24-word mnemonic: %w", err)
	}
	cakePhrase, err := cakePhraseFromMnemonic(mnemonic24)
	if err != nil {
		return err
	}
	cakeAddresses, err := coin.DeriveAddresses(cakePhrase, defaultAddressCount)
	if err != nil {
		return fmt.Errorf("failed to derive %s cake addresses: %w", coin.DisplayName, err)
	}

	out := termout.New()

	// Section 1: the default CryptoNote legacy output, unchanged.
	out.Blank()
	out.DoubleDelimitedBlock(coin.SeedLabel, legacySeed, true)
	out.BlankPair()
	out.Block(strings.ToUpper(coin.DisplayName)+" PRIMARY ADDRESS", legacyAddresses.PrimaryAddress, false)
	if len(legacyAddresses.Subaddresses) > 0 {
		out.BlankPair()
		out.RawBorderBlock("----- "+coin.AddressLabel+" -----", subaddressLines(legacyAddresses.Subaddresses))
	}
	out.BlankPair()

	// Divider between the two sections.
	out.AsteriskDivider()

	// Section 2: the 24-word MELT phrase (Unstoppable) and the 25-word Cake
	// phrase in one shared-end block, then the Cake addresses.
	out.Blank()
	out.SharedEndBlock(
		[]string{moneroUnstoppableSeedLabel, moneroCakeSeedLabel},
		[]string{mnemonic24, cakePhrase},
		moneroMergedSeedEndLabel,
	)
	out.BlankPair()
	out.Block("MONERO PRIMARY ADDRESS (CAKE WALLET)", cakeAddresses.PrimaryAddress, false)
	if len(cakeAddresses.Subaddresses) > 0 {
		out.BlankPair()
		out.RawBorderBlock("----- MONERO ADDRESSES FROM CAKE WALLET 25-WORD SEED -----", subaddressLines(cakeAddresses.Subaddresses))
	}
	out.BlankPair()
	return nil
}

func subaddressLines(subaddresses []string) []termout.BlockLine {
	lines := make([]termout.BlockLine, 0, len(subaddresses))
	for i, subaddress := range subaddresses {
		lines = append(lines, termout.BlockLine{Text: fmt.Sprintf("subaddress 0,%d %s", i+1, subaddress)})
	}
	return lines
}
