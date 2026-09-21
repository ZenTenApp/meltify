package derive

import (
	"crypto/ed25519"
	"fmt"
	"math"
	"time"

	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
)

const (
	msPerSecond = 1000
	braveEpoch  = "Tue, 10 May 2022 00:00:00 GMT"
)

// Mnemonic24 returns the 24-word BIP39 English phrase for an Ed25519 seed.
//
// This matches seedify.ToMnemonicWithLength(key, 24, "", false, 0): the raw
// 32-byte seed is used as BIP39 entropy with no word-count prefix or extra hash.
func Mnemonic24(key *ed25519.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("nil ed25519 key")
	}
	words, err := bip39.NewMnemonic(key.Seed())
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}
	return words, nil
}

// BraveSync25thWord returns Brave Sync's daily 25th BIP39 word for today UTC.
func BraveSync25thWord() (string, error) {
	return BraveSync25thWordForDate(time.Now().UTC())
}

// BraveSync25thWordForDate returns Brave Sync's 25th word for date (UTC).
//
// Adapted from github.com/ZenTenApp/seedify (MIT): days since
// 2022-05-10 00:00:00 GMT, rounded the way JavaScript Math.round does,
// index the BIP39 English word list.
func BraveSync25thWordForDate(date time.Time) (string, error) {
	epochDate, err := time.Parse(time.RFC1123, braveEpoch)
	if err != nil {
		return "", fmt.Errorf("could not parse epoch date: %w", err)
	}
	epochDate = epochDate.UTC()
	dateUTC := date.UTC()

	deltaInMsec := dateUTC.Sub(epochDate).Milliseconds()
	deltaInDays := float64(deltaInMsec) / (24 * 60 * 60 * msPerSecond)
	deltaInDaysRounded := int64(math.Round(deltaInDays))
	if deltaInDaysRounded < 0 {
		return "", fmt.Errorf("date %s is before the epoch date %s", dateUTC.Format(time.RFC1123), epochDate.Format(time.RFC1123))
	}

	wordList := wordlists.English
	if deltaInDaysRounded >= int64(len(wordList)) {
		return "", fmt.Errorf("calculated index %d is out of bounds for BIP39 word list (max index: %d)", deltaInDaysRounded, len(wordList)-1)
	}
	return wordList[deltaInDaysRounded], nil
}
