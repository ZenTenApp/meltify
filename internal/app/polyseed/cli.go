// Package polyseed provides the meltify-polyseed CLI executable logic.
package polyseed

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
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

	// polyseedMinBirthdayUnix is the Polyseed format's epoch timestamp,
	// 1 Nov 2021 12:00 UTC (github.com/complex-gh/polyseed_go). It is the
	// first possible polyseed birthday, so --all-polyseeds enumerates every
	// unique birthday period from this era through today. The calendar-day
	// iteration below samples each day at 00:00 UTC (matching seedify's
	// groupPolyseedsByDay), starting from 1 Nov 2021 00:00 UTC.
	polyseedMinBirthdayUnix = uint64(1635768000)
)

// polyseedDayGroup holds a unique 16-word polyseed mnemonic together with the
// inclusive calendar-day range over which that mnemonic is produced.
//
// The polyseed birthday has a resolution of ~30.44 days (the birthday is
// encoded as (unix-epoch)/step), and the period grid drifts against calendar
// months, so consecutive days that fall within the same birthday step yield
// identical mnemonics. groupPolyseedsByDay walks every day from the Polyseed
// epoch to today and merges those runs, matching seedify's --all-polyseeds.
//
// Note: because the grid is not month-aligned, a calendar --birthday YYYY-MM
// (i.e. the 1st of the month at 00:00 UTC) can fall inside the *previous*
// period, so a --birthday phrase may differ from the --all-polyseeds chunk
// that covers most of that month. This matches seedify's own behavior.
type polyseedDayGroup struct {
	mnemonic  string
	startDate time.Time
	endDate   time.Time
}

// allPolyseeds returns every unique polyseed from the first possible birthday
// (1 Nov 2021, the Polyseed era) through today, in chronological order.
// Consecutive days producing an identical mnemonic are merged into a single
// group.
//
// Each calendar day is sampled at 00:00 UTC, exactly like seedify's
// groupPolyseedsByDay. Sampling at the epoch timestamp itself (12:00 UTC)
// would mis-assign boundary days whose period flip falls within the day, so
// the loop must start at midnight of the epoch calendar day.
func allPolyseeds(key *ed25519.PrivateKey) ([]polyseedDayGroup, error) {
	start := time.Date(2021, time.November, 1, 0, 0, 0, 0, time.UTC)
	now := time.Now().UTC()

	var groups []polyseedDayGroup
	var prev string

	for current := start; !current.After(now); current = current.AddDate(0, 0, 1) {
		mnemonic, err := seedify.ToMnemonicWithLength(key, polyseedWordCount, "", false, uint64(current.Unix())) //nolint:gosec
		if err != nil {
			return nil, fmt.Errorf("could not generate polyseed for %s: %w", current.Format("2006-01-02"), err)
		}

		if mnemonic != prev {
			groups = append(groups, polyseedDayGroup{
				mnemonic:  mnemonic,
				startDate: current,
				endDate:   current,
			})
			prev = mnemonic
		} else {
			groups[len(groups)-1].endDate = current
		}
	}

	return groups, nil
}

// ExecutePolyseed runs the meltify-polyseed CLI.
func ExecutePolyseed(args []string, stdin io.Reader, info cliutil.VersionInfo) error {
	cmd := newRootCommand(stdin, info)
	cmd.SetArgs(args)
	return cmd.Execute() //nolint:wrapcheck // Preserve Cobra's command error formatting.
}

func newRootCommand(stdin io.Reader, info cliutil.VersionInfo) *cobra.Command {
	var subaccount string
	var birthday string
	var allPolyseeds bool

	rootCmd := &cobra.Command{
		Use:   binaryName + " [key-path]",
		Short: "Export a deterministic 16-word Monero polyseed and addresses from an Ed25519 OpenSSH key",
		Long: `meltify-polyseed runs meltify to extract raw Ed25519 seed material, then derives a deterministic
16-word Monero polyseed (Polyseed format) from that seed. The polyseed's embedded creation date
(the "birthday") defaults to January 1 of the current year, matching the seedify CLI; use
--birthday YYYY-MM to override, or --all-polyseeds to emit every unique polyseed from the first
possible birthday (November 2021) through today. The same key, subaccount, and birthday always
produce the same phrase.

With --all-polyseeds the output is one polyseed block per unique birthday period, labeled with the
calendar-day range it covers (e.g. 2021-11-01 → 2021-12-01), matching seedify's --all-polyseeds.

The output is the 16-word polyseed phrase plus the Monero primary address and subaddresses derived
from it (single-birthday mode only). The polyseed phrase is self-contained: restoring it in any
standard Monero wallet reproduces exactly these addresses (no seed-offset passphrase is supported,
since the polyseed format has no slot for one). Encrypted keys prompt for the existing SSH key
passphrase. Use --subaccount to derive a deterministic subaccount key first.`,
		Example: `  meltify-polyseed ~/.ssh/id_ed25519
  cat ~/.ssh/id_ed25519 | meltify-polyseed
  meltify-polyseed ~/.ssh/id_ed25519 --subaccount subaccount-label
  meltify-polyseed ~/.ssh/id_ed25519 --birthday 2024-06
  meltify-polyseed ~/.ssh/id_ed25519 --all-polyseeds`,
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
			return runWithOptions(keyPath, subaccount, birthday, allPolyseeds, stdin)
		},
	}
	rootCmd.Flags().StringVarP(&subaccount, "subaccount", "s", "", "Derive a deterministic subaccount key from the source key and an arbitrary subaccount label")
	rootCmd.Flags().StringVar(&birthday, "birthday", "", "Polyseed creation date as YYYY-MM (default: January 1 of the current year)")
	rootCmd.Flags().BoolVar(&allPolyseeds, "all-polyseeds", false, "Generate every unique polyseed from the first possible birthday (Nov 2021) through today, one block per unique birthday period (overrides --birthday)")
	rootCmd.AddCommand(cliutil.NewManCommand(rootCmd))
	rootCmd.AddCommand(cliutil.NewCompletionCommand(rootCmd, binaryName))
	return rootCmd
}

func runWithOptions(keyPath, subaccount, birthday string, allPolyseeds bool, stdin io.Reader) error {
	seed, err := meltifyexec.ExtractSeed(keyPath, subaccount, stdin)
	if err != nil {
		return fmt.Errorf("could not extract key material with meltify: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	if allPolyseeds {
		return printAllPolyseeds(&key)
	}

	birthdayUnix, birthdayLabel, err := resolveBirthday(birthday)
	if err != nil {
		return err
	}

	phrase, err := seedify.ToMnemonicWithLength(&key, polyseedWordCount, "", false, birthdayUnix)
	if err != nil {
		return fmt.Errorf("failed to derive Monero polyseed: %w", err)
	}

	keys, err := seedify.DeriveMoneroKeys(phrase, defaultAddressCount)
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

// printAllPolyseeds renders one block per unique polyseed from the first
// possible birthday (Nov 2021) through today, labeled with the inclusive
// calendar-day range each phrase covers. This mirrors seedify's
// --all-polyseeds output (labels like "16-WORD POLYSEED (2021-11-01 →
// 2021-12-01)"), where a token-equivalent phrase is produced across all days
// inside the same ~30.44-day birthday period.
func printAllPolyseeds(key *ed25519.PrivateKey) error {
	groups, err := allPolyseeds(key)
	if err != nil {
		return fmt.Errorf("failed to enumerate all polyseeds: %w", err)
	}

	out := termout.New()
	out.Blank()
	for _, g := range groups {
		label := fmt.Sprintf("16-WORD POLYSEED (%s → %s)", g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"))
		out.Block(label, g.mnemonic, true)
		out.BlankPair()
	}
	return nil
}

// resolveBirthday converts an optional --birthday YYYY-MM override into a Unix
// timestamp. The default is January 1 of the current year, matching the seedify
// CLI. Returns the timestamp and a YYYY-MM label for display.
func resolveBirthday(birthday string) (uint64, string, error) {
	var ts time.Time
	if birthday != "" {
		parsed, err := time.Parse("2006-01", birthday)
		if err != nil {
			return 0, "", fmt.Errorf("invalid --birthday %q: use YYYY-MM (e.g. 2026-01)", birthday)
		}
		ts = parsed
	} else {
		ts = time.Date(time.Now().Year(), time.January, 1, 0, 0, 0, 0, time.UTC)
	}

	label := ts.Format("2006-01")
	unix := ts.Unix()
	if unix < int64(polyseedMinBirthdayUnix) {
		return 0, "", fmt.Errorf("--birthday %s is before the Polyseed era (November 2021); the earliest supported date is 2021-11", label)
	}
	return uint64(unix), label, nil //nolint:gosec // unix is validated >= 2021-11, so it is always non-negative.
}
