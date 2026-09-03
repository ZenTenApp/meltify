package cryptonote

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ZenTenApp/meltify/internal/app/bchat"
)

// TestBchatChatIDEqFromDecodedPhrase is the regression test for a Beldex
// chat-ID mismatch between meltify and the BChat app:
//
// The printed 25-word legacy phrase encodes scReduce32(rawSeed). When that
// phrase is restored in BChat, the app derives the chat ID from the decoded
// (reduced) seed. meltify must therefore derive the chat ID from the same
// reduced bytes — not from the raw Ed25519 seed.
func TestBchatChatIDEqFromDecodedPhrase(t *testing.T) {
	// A seed >= the curve order L, so scReduce32 necessarily changes it.
	raw, err := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatalf("bad raw seed: %v", err)
	}
	key := ed25519.NewKeyFromSeed(raw)

	if equalBytes(scReduce32(key.Seed()), key.Seed()) {
		t.Fatal("test precondition: expected scReduce32 to change the seed")
	}

	phrase, err := legacySeedFromKey(&key)
	if err != nil {
		t.Fatalf("legacySeedFromKey: %v", err)
	}
	recovered := decodeLegacyWordsForTest(strings.Fields(phrase)[:24])
	if !equalBytes(recovered, scReduce32(key.Seed())) {
		t.Fatalf("decoded phrase != reduced seed:\n got %x\nwant %x", recovered, scReduce32(key.Seed()))
	}

	// The chat ID BChat will show after restoring the printed phrase:
	want, err := bchat.DeriveChatID(recovered)
	if err != nil {
		t.Fatalf("DeriveChatID(decoded phrase): %v", err)
	}

	// What meltify prints:
	got, err := BeldexConfig.DeriveExtra(legacySeedBytesFromKey(&key))
	if err != nil {
		t.Fatalf("DeriveExtra: %v", err)
	}
	if got != want {
		t.Errorf("chat ID from reduced legacy seed = %s, want app-equivalent %s (derived from decoded phrase)", got, want)
	}
}

// TestBchatChatIDFld21KnownVector locks the real-world reported discrepancy.
// Restoring this exact 25-word phrase in BChat shows chat ID
// bd225d6c...fd22; meltify must print the same value.
func TestBchatChatIDFld21KnownVector(t *testing.T) {
	const phrase = "rural juvenile younger skydive sincerely folding southern ourselves alarms gutter vogue angled wiring legion nuance unquoted impel duets haystack soda dented aphid possible rigid rigid"
	const bchatAppChatID = "bd225d6cdf8e4b27901a1f38317c341e7f9d62474db621feab3ccdce019c43fd22"

	recovered := decodeLegacyWordsForTest(strings.Fields(phrase)[:24])
	got, err := bchat.DeriveChatID(recovered)
	if err != nil {
		t.Fatalf("DeriveChatID: %v", err)
	}
	if got != bchatAppChatID {
		t.Errorf("chat ID from decoded phrase = %s, want BChat app value %s", got, bchatAppChatID)
	}
}

// decodeLegacyWordsForTest inverts moneroLegacyBytesToWords for the first 24
// words of a legacy phrase (checksum word excluded).
func decodeLegacyWordsForTest(body []string) []byte {
	out := make([]byte, 0, 32)
	for i := 0; i < len(body); i += 3 {
		w1 := legacyWordIndexForTest(body[i])
		w2 := legacyWordIndexForTest(body[i+1])
		w3 := legacyWordIndexForTest(body[i+2])
		x := w1 + moneroLegacyRadix*((moneroLegacyRadix-w1+w2)%moneroLegacyRadix) +
			moneroLegacyRadix*moneroLegacyRadix*((moneroLegacyRadix-w2+w3)%moneroLegacyRadix)
		out = append(out, byte(x), byte(x>>8), byte(x>>16), byte(x>>24))
	}
	return out
}

func legacyWordIndexForTest(w string) int {
	for i, ww := range moneroLegacyWordlist {
		if ww == w {
			return i
		}
	}
	panic("word not in legacy wordlist: " + w)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}