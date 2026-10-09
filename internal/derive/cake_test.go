package derive

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"
)

const abandonAbout = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func TestCakeSpendKeySizeAndOrder(t *testing.T) {
	spend, err := CakeSpendKey(abandonAbout, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(spend) != cakeKeySize {
		t.Fatalf("spend key length = %d, want %d", len(spend), cakeKeySize)
	}
	n := new(big.Int).SetBytes(reverseBytes(spend))
	if n.Cmp(ed25519Order) >= 0 {
		t.Fatalf("spend key is not reduced modulo l: %x", spend)
	}
	if n.Sign() == 0 {
		t.Fatal("spend key is zero")
	}
}

func TestCakeSpendKeyDiffersFromLegacyReducedSeed(t *testing.T) {
	key := ed25519.NewKeyFromSeed(FixedSeed00to1f)
	mnemonic, err := Mnemonic24(&key)
	if err != nil {
		t.Fatal(err)
	}
	cake, err := CakeSpendKey(mnemonic, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cake) == GoldenReducedSeedHex {
		t.Fatal("Cake spend key matched CryptoNote scReduce32 seed; conversion is a no-op")
	}
}

func TestCakeSpendKeyDeterministic(t *testing.T) {
	a, err := CakeSpendKey(GoldenMnemonic24, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CakeSpendKey(GoldenMnemonic24, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatalf("CakeSpendKey not deterministic: %x vs %x", a, b)
	}
	account1, err := CakeSpendKey(GoldenMnemonic24, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(account1) == hex.EncodeToString(a) {
		t.Fatal("account 1 spend key matched account 0")
	}
}

func TestCakeSpendKeyGoldenMnemonic24(t *testing.T) {
	spend, err := CakeSpendKey(GoldenMnemonic24, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(spend)
	if GoldenCakeSpendKeyHex == "" {
		t.Fatalf("fill GoldenCakeSpendKeyHex = %s", got)
	}
	if got != GoldenCakeSpendKeyHex {
		t.Errorf("Cake spend key = %s, want %s", got, GoldenCakeSpendKeyHex)
	}
}
