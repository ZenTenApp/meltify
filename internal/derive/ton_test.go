package derive

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func TestTonV4R2PublishedCodeHash(t *testing.T) {
	got := hex.EncodeToString(tonV4R2CodeHash[:])
	const want = "feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0"
	if got != want {
		t.Errorf("V4R2 code hash = %s, want %s", got, want)
	}
}

func TestEncodeTonV4R2UQZeroPublicKey(t *testing.T) {
	got := encodeTonV4R2UQ(make(ed25519.PublicKey, ed25519.PublicKeySize))
	const want = "UQDwxMHGmoIn936giNrdit8UYQyN42F3lBHFxDxFqic35mIP"
	if got != want {
		t.Errorf("zero pubkey UQ = %s, want %s", got, want)
	}
}

func TestTonAbandonMnemonic(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	got, err := Ton(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	const want = "UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY"
	if got != want {
		t.Errorf("Ton(abandon) = %s, want %s", got, want)
	}
}
