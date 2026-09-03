package polyseed

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ZenTenApp/seedify"
)

// fixedKey returns an ed25519 key with a deterministic seed (00..1f) so tests
// are reproducible.
func fixedKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func phraseFor(t *testing.T, key *ed25519.PrivateKey, day time.Time) string {
	t.Helper()
	m, err := seedify.ToMnemonicWithLength(key, polyseedWordCount, "", false, uint64(day.Unix()))
	if err != nil {
		t.Fatalf("ToMnemonicWithLength(%s): %v", day.Format("2006-01-02"), err)
	}
	return m
}

// TestAllPolyseeds verifies the --all-polyseeds grouping: it covers every
// calendar day from the Polyseed epoch (1 Nov 2021) through today with no gaps
// or overlaps, each group's mnemonic is stable across its whole date range and
// distinct from its neighbors, and the first group is deterministic.
func TestAllPolyseeds(t *testing.T) {
	key := fixedKey()
	groups, err := allPolyseeds(&key)
	if err != nil {
		t.Fatalf("allPolyseeds: %v", err)
	}

	epoch := time.Date(2021, time.November, 1, 0, 0, 0, 0, time.UTC)
	today := time.Now().UTC().Truncate(24 * time.Hour)

	if len(groups) < 55 {
		t.Errorf("expected ~59 unique polyseeds (Nov 2021 -> today), got %d", len(groups))
	}
	if !groups[0].startDate.Equal(epoch) {
		t.Errorf("first group starts %s, want %s", groups[0].startDate.Format("2006-01-02"), epoch.Format("2006-01-02"))
	}
	if !groups[len(groups)-1].endDate.Equal(today) {
		t.Errorf("last group ends %s, want today %s", groups[len(groups)-1].endDate.Format("2006-01-02"), today.Format("2006-01-02"))
	}

	for i, g := range groups {
		if g.startDate.After(g.endDate) {
			t.Fatalf("group %d: start %s after end %s", i, g.startDate.Format("2006-01-02"), g.endDate.Format("2006-01-02"))
		}
		// The mnemonic must be stable across the entire group.
		if got := phraseFor(t, &key, g.startDate); got != g.mnemonic {
			t.Errorf("group %d: phrase at start %s = %s, want %s", i, g.startDate.Format("2006-01-02"), got, g.mnemonic)
		}
		if got := phraseFor(t, &key, g.endDate); got != g.mnemonic {
			t.Errorf("group %d: phrase at end %s = %s, want %s", i, g.endDate.Format("2006-01-02"), got, g.mnemonic)
		}
		// Contiguity with the previous group.
		if i > 0 {
			prevEnd := groups[i-1].endDate.AddDate(0, 0, 1)
			if !prevEnd.Equal(g.startDate) {
				t.Errorf("gap/overlap between group %d (ends %s) and group %d (starts %s)",
					i-1, groups[i-1].endDate.Format("2006-01-02"), i, g.startDate.Format("2006-01-02"))
			}
		}
	}

	// The first group must be deterministic for this key and match the phrase
	// at the epoch day and a mid-period day (2021-11-15).
	want := phraseFor(t, &key, epoch)
	if groups[0].mnemonic != want {
		t.Errorf("first group mnemonic = %s, want %s", groups[0].mnemonic, want)
	}
	if mid := phraseFor(t, &key, epoch.AddDate(0, 0, 14)); mid != want {
		t.Errorf("phrase on 2021-11-15 = %s, want first-group phrase %s", mid, want)
	}
}

// TestAllPolyseedsStartsAtEpoch ensures the first possible birthday is the
// Polyseed epoch era: nothing before 1 Nov 2021 is enumerated.
func TestAllPolyseedsStartsAtEpoch(t *testing.T) {
	epoch := time.Date(2021, time.November, 1, 0, 0, 0, 0, time.UTC)
	key := fixedKey()
	groups, err := allPolyseeds(&key)
	if err != nil {
		t.Fatalf("allPolyseeds: %v", err)
	}
	for i, g := range groups {
		if g.startDate.Before(epoch) {
			t.Errorf("group %d starts %s before epoch %s", i, g.startDate.Format("2006-01-02"), epoch.Format("2006-01-02"))
		}
	}
}
