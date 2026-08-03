// Package cryptonote provides CLIs for CryptoNote-family meltify executables.
package cryptonote

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/sshkey"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/ZenTenApp/seedify"
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
	BinaryName         string
	DisplayName        string
	Symbol             string
	SeedLabel          string
	AddressLabel       string
	SupportsSeedOffset bool
	DeriveAddresses    func(seed string, count int, seedOffset string) (AddressSet, error)
}

// BeldexConfig configures meltify-beldex.
var BeldexConfig = CoinConfig{
	BinaryName:   "meltify-beldex",
	DisplayName:  "Beldex",
	Symbol:       "BDX",
	SeedLabel:    "25-WORD BELDEX (BDX) SEED",
	AddressLabel: "BELDEX ADDRESSES FROM 25-WORD SEED",
	DeriveAddresses: func(seed string, count int, _ string) (AddressSet, error) {
		keys, err := seedify.DeriveBeldexKeysFromLegacySeed(seed, count)
		if err != nil {
			return AddressSet{}, fmt.Errorf("derive Beldex keys from legacy seed: %w", err)
		}
		return AddressSet{PrimaryAddress: keys.PrimaryAddress, Subaddresses: keys.Subaddresses}, nil
	},
}

// MoneroConfig configures the future meltify-monero executable.
var MoneroConfig = CoinConfig{
	BinaryName:         "meltify-monero",
	DisplayName:        "Monero",
	Symbol:             "XMR",
	SeedLabel:          "25-WORD MONERO LEGACY SEED",
	AddressLabel:       "MONERO ADDRESSES FROM 25-WORD LEGACY SEED",
	SupportsSeedOffset: true,
	DeriveAddresses: func(seed string, count int, seedOffset string) (AddressSet, error) {
		keys, err := seedify.DeriveMoneroKeysFromLegacySeedWithSeedOffset(seed, count, seedOffset)
		if err != nil {
			return AddressSet{}, fmt.Errorf("derive Monero keys from legacy seed: %w", err)
		}
		return AddressSet{PrimaryAddress: keys.PrimaryAddress, Subaddresses: keys.Subaddresses}, nil
	},
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
	var seedOffset string

	rootCmd := &cobra.Command{
		Use:   coin.BinaryName + " [key-path]",
		Short: fmt.Sprintf("Export %s seed and addresses from an Ed25519 OpenSSH key", coin.DisplayName),
		Long: fmt.Sprintf(`%[1]s derives a deterministic %[2]s seed and addresses from an Ed25519 OpenSSH private key.

Encrypted keys prompt for the existing SSH key passphrase. Use --subaccount to derive a deterministic subaccount key first.`, coin.BinaryName, coin.DisplayName),
		Example: fmt.Sprintf(`  %[1]s ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | %[1]s
  %[1]s ~/.ssh/id_ed25519 --subaccount subaccount-label`, coin.BinaryName),
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
			return runWithOptions(keyPath, subaccount, seedOffset, stdin, coin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	if coin.SupportsSeedOffset {
		rootCmd.Flags().StringVar(&seedOffset, "seed-offset", "", fmt.Sprintf("%s seed offset passphrase", coin.DisplayName))
	}
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, coin.BinaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, seedOffset string, stdin io.Reader, coin CoinConfig) error {
	material, err := sshkey.LoadEd25519Key(keyPath, stdin)
	if err != nil {
		return fmt.Errorf("could not load SSH key: %w", err)
	}
	if err := material.ActivateSubaccount(subaccount); err != nil {
		return fmt.Errorf("could not activate subaccount: %w", err)
	}
	return printCoinOutput(material.Key, seedOffset, coin)
}

func printCoinOutput(key *ed25519.PrivateKey, seedOffset string, coin CoinConfig) error {
	seed, err := legacySeedFromKey(key)
	if err != nil {
		return fmt.Errorf("failed to derive %s seed: %w", coin.DisplayName, err)
	}

	addresses, err := coin.DeriveAddresses(seed, defaultAddressCount, seedOffset)
	if err != nil {
		return fmt.Errorf("failed to derive %s addresses: %w", coin.DisplayName, err)
	}

	out := termout.New()
	out.Blank()
	out.DoubleDelimitedBlock(coin.SeedLabel, seed, true)
	out.BlankPair()
	out.Block(strings.ToUpper(coin.DisplayName)+" PRIMARY ADDRESS", addresses.PrimaryAddress, false)
	if len(addresses.Subaddresses) > 0 {
		out.BlankPair()
		out.RawBorderBlock("----- "+coin.AddressLabel+" -----", subaddressLines(addresses.Subaddresses))
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
