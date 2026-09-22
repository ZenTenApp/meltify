package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	polyseed "github.com/complex-gh/polyseed_go"
)

const (
	polyseedWordCount    = 16
	wordCountBytesSize   = 2
	polyseedEntropyBytes = 19
)

// Polyseed16 returns the 16-word Monero polyseed for key and birthday.
//
// This matches seedify.ToMnemonicWithLength(key, 16, "", false, birthday):
// SHA-256(uint16(16) || seed)[:19] is fed to polyseed with that birthday.
// birthday 0 means "now", same as polyseed_go.
func Polyseed16(key *ed25519.PrivateKey, birthday uint64) (string, error) {
	if key == nil {
		return "", fmt.Errorf("nil ed25519 key")
	}
	fullSeed := key.Seed()
	wordCountBytes := make([]byte, wordCountBytesSize)
	binary.BigEndian.PutUint16(wordCountBytes, uint16(polyseedWordCount))

	prefixedSeed := make([]byte, len(wordCountBytes)+len(fullSeed))
	copy(prefixedSeed, wordCountBytes)
	copy(prefixedSeed[len(wordCountBytes):], fullSeed)

	hash := sha256.Sum256(prefixedSeed)
	polyseedBytes := hash[:polyseedEntropyBytes]

	seed, err := polyseed.CreateFromBytesWithBirthday(polyseedBytes, 0, birthday)
	if err != nil {
		return "", fmt.Errorf("could not create polyseed: %w", err)
	}
	defer seed.Free()

	lang := polyseed.GetLang(0)
	if lang == nil {
		return "", fmt.Errorf("could not get polyseed language")
	}
	return seed.Encode(lang, polyseed.CoinMonero), nil
}
