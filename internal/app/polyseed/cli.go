// Package polyseed provides the meltify-polyseed CLI executable logic.
package polyseed

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ZenTenApp/meltify/internal/cliutil"
	"github.com/ZenTenApp/meltify/internal/meltifyexec"
	"github.com/ZenTenApp/meltify/internal/termout"
	"github.com/ZenTenApp/seedify"
	"github.com/spf13/cobra"
)

const (
	binaryName          = "meltify-polyseed"
	defaultAddressCount = 9
	polyseedWordCount   = 16

	// polyseedMinBirthdayUnix is the start of the Polyseed format era
	// (November 2021), from github.com/complex-gh/polyseed_go.
	polyseedMinBirthdayUnix = uint64(1635768000)
)

// ExecutePolyseed runs the meltify-polyseed CLI.
func ExecutePolyseed(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string
	var seedOffset string
	var birthday string

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic 16-word Monero polyseed and addresses from an Ed25519 OpenSSH key",
		Long: `meltify-polyseed runs meltify to extract raw Ed25519 seed material, then derives a deterministic
16-word Monero polyseed (Polyseed format) from that seed. The polyseed's embedded creation date
(the "birthday") defaults to January 1 of the current year, matching the seedify CLI; use
--birthday YYYY-MM to override. The same key, subaccount, and birthday always produce the same phrase.

The output is the 16-word polyseed phrase plus the Monero primary address and subaddresses derived
from it. Encrypted keys prompt for the existing SSH key passphrase. Use --subaccount to derive a
deterministic subaccount key first.`,
		Example: `  meltify-polyseed ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-polyseed
  meltify-polyseed ~/.ssh/id_ed25519 --subaccount subaccount-label
  meltify-polyseed ~/.ssh/id_ed25519 --seed-offset my-offset
  meltify-polyseed ~/.ssh/id_ed25519 --birthday 2024-06`,
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
			return runWithOptions(keyPath, subaccount, seedOffset, birthday, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&seedOffset, "seed-offset", "", "Monero seed offset passphrase (Feather-compatible)")
	rootCmd.Flags().StringVar(&birthday, "birthday", "", "Polyseed creation date as YYYY-MM (default: January 1 of the current year)")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, seedOffset, birthday string, stdin io.Reader) error {
	seed, err := meltifyexec.ExtractSeed(keyPath, subaccount, stdin)
	if err != nil {
		return fmt.Errorf("could not extract key material with meltify: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	birthdayUnix, birthdayLabel, err := resolveBirthday(birthday)
	if err != nil {
		return err
	}

	phrase, err := seedify.ToMnemonicWithLength(&key, polyseedWordCount, "", false, birthdayUnix)
	if err != nil {
		return fmt.Errorf("failed to derive Monero polyseed: %w", err)
	}

	keys, err := seedify.DeriveMoneroKeysWithSeedOffset(phrase, defaultAddressCount, seedOffset)
	if err != nil {
		return fmt.Errorf("failed to derive Monero keys from polyseed: %w", err)
	}

	out := termout.New()
	out.Blank()
	out.DoubleDelimitedBlock("16-WORD MONERO POLYSEED (BIRTHDAY "+birthdayLabel+")", phrase, true)
	out.BlankPair()
	out.Block("MONERO PRIMARY ADDRESS", keys.PrimaryAddress, false)
	if len(keys.Subaddresses) > 0 {
		out.BlankPair()
		out.RawBorderBlock("----- MONERO ADDRESSES FROM POLYSEED -----", subaddressLines(keys.Subaddresses))
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

// resolveBirthday converts an optional --birthday YYYY-MM override into a Unix
// timestamp. The default is January 1 of the current year, matching the seedify
// CLI. Returns the timestamp and a YYYY-MM label for display.
func resolveBirthday(birthday string) (uint64, string, error) {
	year, month := time.Now().Year(), time.January
	if birthday != "" {
		parts := strings.SplitN(birthday, "-", 2)
		if len(parts) != 2 {
			return 0, "", fmt.Errorf("invalid --birthday %q: use YYYY-MM (e.g. 2026-01)", birthday)
		}
		y, err := strconv.Atoi(parts[0])
		if err != nil {
			return 0, "", fmt.Errorf("invalid --birthday %q: use YYYY-MM (e.g. 2026-01)", birthday)
		}
		m, err := strconv.Atoi(parts[1])
		if err != nil || m < 1 || m > 12 {
			return 0, "", fmt.Errorf("invalid --birthday %q: use YYYY-MM (e.g. 2026-01)", birthday)
		}
		year, month = y, time.Month(m)
	}

	ts := time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
	label := ts.Format("2006-01")
	if uint64(ts.Unix()) < polyseedMinBirthdayUnix {
		return 0, "", fmt.Errorf("--birthday %s is before the Polyseed era (November 2021); the earliest supported date is 2021-11", label)
	}
	return uint64(ts.Unix()), label, nil
}